/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#pragma once

#include <appbase/application.hpp>
#include <eosio/chain/asset.hpp>
#include <eosio/chain/authority.hpp>
#include <eosio/chain/account_object.hpp>
#include <eosio/chain/block.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/contract_table_objects.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/chain/transaction.hpp>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/chain/types.hpp>
#include <eosio/chain/memory_db.hpp>

#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/config_on_chain.hpp>
#include <eosio/chain/txfee_manager.hpp>
#include <fc/io/fstream.hpp>
#include <fc/io/json.hpp>

#include <boost/container/flat_set.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/algorithm/string.hpp>


#include <fc/static_variant.hpp>


namespace fc { class variant; }

namespace eosio {
    using chain::controller;
    using std::unique_ptr;
    using std::pair;
    using namespace appbase;
    using chain::name;
    using chain::uint128_t;
    using chain::int128_t;
    using chain::public_key_type;
    using chain::transaction;
    using chain::transaction_id_type;
    using fc::optional;
    using boost::container::flat_set;
    using chain::asset;
    using chain::symbol;
    using chain::authority;
    using chain::account_name;
    using chain::action_name;
    using chain::abi_def;
    using chain::abi_serializer;

    using bytes               = vector<char>;
    void load_contract_code_abi(const string &contract, bytes &code, bytes &abi);

    namespace chain_apis {

        const auto sys_account = chain::config::system_account_name;

        struct by_code_scope_table;
        struct by_scope_primary;

        struct read_only_eforce {
            const controller &db;
            const fc::microseconds &abi_serializer_max_time;
            const bool &shorten_abi_errors;

            read_only_eforce(const controller &_db, const fc::microseconds &abi_maxtime, const bool &shorten_abi_errors)
                    : db(_db), abi_serializer_max_time(abi_maxtime), shorten_abi_errors(shorten_abi_errors) {}

            static void copy_inline_row(const chain::key_value_object &obj, vector<char> &data) {
                data.resize(obj.value.size());
                memcpy(data.data(), obj.value.data(), obj.value.size());
            }

        public:
            // some helper funcs for get data from table in chain
            inline uint64_t get_table_index(const uint64_t &table, const uint64_t &pos) const {
                auto index = table & 0xFFFFFFFFFFFFFFF0ULL;
                EOS_ASSERT(index == table, chain::contract_table_query_exception, "Unsupported table name: ${n}",
                           ("n", table));
                index |= (pos & 0x000000000000000FULL);
                return index;
            }

            std::vector<fc::variant> get_table_rows_by_primary_to_json(const name &code,
                                                                       const uint64_t &scope,
                                                                       const name &table,
                                                                       const abi_serializer &abis,
                                                                       const std::size_t max_size) const {
                std::vector<fc::variant> result;

                const auto &d = db.db();

                const auto *t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(
                        boost::make_tuple(code, scope, table));
                if (t_id != nullptr) {
                    const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
                    result.reserve(max_size);

                    decltype(t_id->id) next_tid(t_id->id._id + 1);
                    const auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
                    const auto upper = idx.lower_bound(boost::make_tuple(next_tid));

                    std::size_t added = 0;
                    vector<char> data;
                    data.reserve(4096);
                    for (auto itr = lower; itr != upper; ++itr) {
                        if (added >= max_size) {
                            break;
                        }
                        copy_inline_row(*itr, data);
                        result.push_back(abis.binary_to_variant(abis.get_table_type(table),
                                                                data,
                                                                abi_serializer_max_time,
                                                                shorten_abi_errors));
                        added++;
                    }
                }

                return result;
            }

            template<typename T>
            bool get_table_row_by_primary_key(const uint64_t &code, const uint64_t &scope,
                                              const uint64_t &table, const uint64_t &id, T &out) const {

                const auto *tab = db.db().find<chain::table_id_object, chain::by_code_scope_table>(
                        boost::make_tuple(code, scope, table));
                if (!tab) {
                    return false;
                }

                const auto *obj = db.db().find<chain::key_value_object, chain::by_scope_primary>(
                        boost::make_tuple(tab->id, id));
                if (!obj) {
                    return false;
                }

                vector<char> data;
                copy_inline_row(*obj, data);
                chain::datastream<const char *> ds(data.data(), data.size());

                fc::raw::unpack(ds, out);

                return true;
            }

            template<typename T>
            void walk_table_by_seckey(const uint64_t &code,
                                      const uint64_t &scope,
                                      const uint64_t &table,
                                      const uint64_t &key,
                                      const std::function<bool(unsigned int, const T &)> &f) const {
                const auto &d = db.db();

                const auto table_with_index = get_table_index(table, 0); // 0 is for the first seckey index

                const auto *t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(
                        boost::make_tuple(code, scope, table));
                const auto *index_t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(
                        boost::make_tuple(code, scope, table_with_index));

                if (t_id != nullptr && index_t_id != nullptr) {
                    const auto &secidx = d.get_index<chain::index64_index, chain::by_secondary>();
                    decltype(index_t_id->id) low_tid(index_t_id->id._id);
                    decltype(index_t_id->id) next_tid(index_t_id->id._id + 1);
                    auto lower = secidx.lower_bound(boost::make_tuple(low_tid, key));
                    auto upper = secidx.lower_bound(boost::make_tuple(low_tid, key + 1));

                    vector<char> data;
                    auto end = fc::time_point::now() + fc::microseconds(1000 * 10); /// 10ms max time

                    unsigned int count = 0;
                    auto itr = lower;
                    T obj;
                    for (; itr != upper; ++itr) {
                        const auto *itr2 = d.find<chain::key_value_object, chain::by_scope_primary>(
                                boost::make_tuple(t_id->id, itr->primary_key)
                        );

                        if (itr2 == nullptr) {
                            continue;
                        }

                        copy_inline_row(*itr2, data);
                        chain::datastream<const char *> ds(data.data(), data.size());
                        fc::raw::unpack(ds, obj);

                        if (f(count, obj)) {
                            break;
                        }

                        ++count;
                        EOS_ASSERT(fc::time_point::now() <= end, chain::contract_table_query_exception,
                                   "walk table cost too much time!");
                    }
                    EOS_ASSERT(itr == upper, chain::contract_table_query_exception, "not walk all item in table!");
                }
            }

            struct get_required_fee_params {
                fc::variant transaction;
            };
            struct get_required_fee_result {
                asset required_fee;
            };

//            get_required_fee_result get_required_fee(const get_required_fee_params &params) const;

            struct get_action_fee_params {
                account_name account;
                action_name action;
            };
            struct get_action_fee_result {
                asset fee;
            };
//
//            get_action_fee_result get_action_fee(const get_action_fee_params &params) const;

            struct get_chain_configs_params {
                name typ;
            };
            struct get_chain_configs_result {
                name typ;
                int64_t num = 0;
                account_name key = 0;
                asset fee;
            };

//            get_chain_configs_result get_chain_configs(const get_chain_configs_params &params) const;


            struct get_vote_rewards_params {
                account_name voter = 0;
                account_name bp_name = 0;
            };

            struct get_vote_rewards_result {
                asset vote_reward;
                uint128_t vote_assetage_sum = 0;
                uint32_t block_num = 0;
                vector<fc::variant> ext_datas;
            };


            // get_vote_rewards get voter 's reward by vote in eosforce
            get_vote_rewards_result
            get_vote_rewards(const get_vote_rewards_params &p) {
                //ilog( "get_vote_rewards ${acc} from ${bp}", ("acc", p.voter)("bp", p.bp_name));

                const auto curr_block_num = db.head_block_num();

                // 1. Need BP total voteage and reward_pool info
                chain::memory_db::bp_info bp_data;
                EOS_ASSERT(get_table_row_by_primary_key(sys_account, sys_account, N(bps), p.bp_name, bp_data),
                           chain::contract_table_query_exception,
                           "cannot find bp info by name ${n}", ("n", p.bp_name));

                //ilog( "bp data: ${data}", ("data", bp_data) );

                const auto bp_total_assetage =
                        (static_cast<int128_t>(bp_data.total_staked)
                         * static_cast<int128_t>(curr_block_num - bp_data.voteage_update_height))
                        + bp_data.total_voteage;

                //ilog( "bp data: ${data} on ${n}", ("data", bp_total_assetage)("n", curr_block_num) );

                uint64_t voter_total_assetage = 0;

                // 2. Need calc voter current vote voteage
                chain::memory_db::vote_info curr_vote_data;
                const auto is_has_curr_vote = get_table_row_by_primary_key(
                        sys_account, p.voter, N(votes), p.bp_name, curr_vote_data);
                if (is_has_curr_vote) {
                    //ilog( "get current vote data : ${d}", ("d", curr_vote_data) );
                    const auto curr_vote_assetage =
                            (static_cast<int128_t>(curr_vote_data.staked.get_amount() /
                                                   curr_vote_data.staked.precision())
                             * static_cast<int128_t>(curr_block_num - curr_vote_data.voteage_update_height))
                            + curr_vote_data.voteage;

                    //ilog( "get current vote assetage : ${d}", ("d", curr_vote_assetage) );
                    voter_total_assetage += curr_vote_assetage;
                }

                // 3. Need calc the sum of voter 's fix-time vote voteage
                walk_table_by_seckey<chain::memory_db::votefix_info>(
                        sys_account, p.voter, N(fixvotes), p.bp_name,
                        [&](unsigned int c, const chain::memory_db::votefix_info &v) -> bool {
                            //ilog("walk fix ${n} : ${data}", ("n", c)("data", v));
                            const auto fix_votepower_age =
                                    (static_cast<int128_t>(v.votepower_age.staked.get_amount() /
                                                           v.votepower_age.staked.precision())
                                     * static_cast<int128_t>(curr_block_num - v.votepower_age.update_height))
                                    + v.votepower_age.age;
                            voter_total_assetage += fix_votepower_age;
                            return false; // no break
                        });

                // 4. Make reward to result
                const auto amount_voteage = static_cast<int128_t>( bp_data.rewards_pool.get_amount())
                                            * voter_total_assetage;
                const auto &reward = asset{
                        bp_total_assetage > 0
                        ? static_cast<int64_t>( amount_voteage / bp_total_assetage )
                        : 0
                };

                return {
                        reward,
                        voter_total_assetage,
                        curr_block_num,
                        {}
                };
            }

            struct get_table_rows_params {
                bool json = false;
                name code;
                string scope;
                name table;
                string table_key;
                string lower_bound;
                string upper_bound;
                uint32_t limit = 10;
                string key_type;  // type of key specified by index_position
                string index_position; // 1 - primary (first), 2 - secondary index (in order defined by multi_index), 3 - third index, etc
                string encode_type{"dec"}; //dec, hex , default=dec
                optional<bool> reverse;
                optional<bool> show_payer; // show RAM pyer
            };


            get_chain_configs_result get_chain_configs(const get_chain_configs_params &params) const {
                const auto &itr = db.db().find<chain::config_data_object, chain::by_name>(params.typ);
                get_chain_configs_result res;
                res.typ = params.typ;

                if (itr != nullptr) {
                    res.num = itr->num;
                    res.key = itr->key;
                    res.fee = itr->fee;
                } else {
                    EOS_ASSERT(false, chain::config_type_exception, "No Config found by name ${t}", ("t", params.typ));
                }
                return res;
            }

            get_required_fee_result get_required_fee(const get_required_fee_params &params) const {
                transaction pretty_input;
                from_variant(params.transaction, pretty_input);
                auto required_fee = db.get_txfee_manager().get_required_fee(db, pretty_input);
                get_required_fee_result result;
                result.required_fee = required_fee;
                return result;
            }

            get_chain_configs_result get_chain_configs(const get_chain_configs_params &params) {
                const auto &itr = db.db().find<chain::config_data_object, chain::by_name>(params.typ);
                get_chain_configs_result res;
                res.typ = params.typ;

                if (itr != nullptr) {
                    res.num = itr->num;
                    res.key = itr->key;
                    res.fee = itr->fee;
                } else {
                    EOS_ASSERT(false, chain::config_type_exception, "No Config found by name ${t}", ("t", params.typ));
                }

                return res;
            }

            get_action_fee_result get_action_fee(const get_action_fee_params &params) {
                return get_action_fee_result{
                        db.get_txfee_manager().get_required_fee(db, params.account, params.action)};
            }
        };


        //Convert the table_key string to the uint64_t. can't supprot combination key
        template<typename table_rows_params>
        static uint64_t get_table_key(const table_rows_params &p1, const abi_def &abi) {

            auto &p = reinterpret_cast<const read_only_eforce::get_table_rows_params &>(p1);

            string key_type;
            for (const auto &t : abi.tables) {
                if (t.name == p.table) {
                    if (t.key_types.empty() || t.key_names.empty()) {
                        EOS_THROW(chain::contract_table_query_exception, "no key_types in table");
                    }
                    key_type = t.key_types[0];
                }
            }

            uint64_t t_key = 0;
            try {
                if (key_type == "account_name" || key_type == "name") {
                    t_key = eosio::chain::string_to_name(p.table_key.c_str());
                } else if (key_type == "uint64" && p.table_key != "") {
                    string trimmed_key_str = p.table_key;
                    boost::trim(trimmed_key_str);
                    t_key = boost::lexical_cast<uint64_t>(trimmed_key_str.c_str(), trimmed_key_str.size());
                }
            } catch (...) {
                FC_THROW("could not convert table_key string to any of the following: valid account_name, uint64_t");
            }
            return t_key;
        }
    } // namespace chain_apis
}


