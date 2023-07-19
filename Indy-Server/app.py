import asyncio
from hashlib import sha256
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import asyncio
import json
import time
import subprocess
from indy import pool, anoncreds, ledger, wallet, did, IndyError
from indy.error import ErrorCode
from helpers import (
    create_wallet,
    getting_verinym,
    get_cred_def,
    get_schema,
    get_credential_for_referent,
    prover_get_entities_from_ledger,
    verifier_get_entities_from_ledger,
    send_cred_def,
    send_schema,
    send_nym,
)
from gevent import monkey
from flask_cors import CORS

monkey.patch_all()

active_wallet = {}

JSON_FILE_LOCATION = "/Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabric/fabric-cli/chaincode.json"

loop = asyncio.get_event_loop()
pool_ = {"name": "pool1"}
steward = {
    "name": "Sovrin Steward",
    "wallet_config": json.dumps({"id": "sovrin_steward_wallet"}),
    "wallet_credentials": json.dumps({"key": "steward_wallet_key"}),
    "pool": None,
    "seed": "000000000000000000000000Steward1",
}
government = {
    "name": "Government",
    "wallet_config": json.dumps({"id": "government_wallet"}),
    "wallet_credentials": json.dumps({"key": "government_wallet_key"}),
    "pool": None,
    "role": "ENDORSER",
}
verismart = {
    "name": "Verismart",
    "wallet_config": json.dumps({"id": "verismart_wallet"}),
    "wallet_credentials": json.dumps({"key": "verismart_wallet_key"}),
    "pool": None,
    "role": "ENDORSER",
}

example_schema = {
    "name": "Verismart-ID",
    "version": "0.2",
    "attributes": [
        "first_name",
        "last_name",
        "salary",
        "employee_status",
        "experience",
    ],
}

installed_wallets = {}
installed_wallets["government"] = government
installed_wallets["steward"] = steward
installed_wallets["verismart"] = verismart

installed_schemas = {}
installed_schemas["example"] = example_schema

installed_schema_ids = {}

app = Flask(__name__)
CORS(app)
# app.config["SECRET_KEY"] = "someKey"
socketio = SocketIO(app, cors_allowed_origins="*")
I32_BOUND = 2**31


def encode(orig) -> str:
    if isinstance(orig, int) and -I32_BOUND <= orig < I32_BOUND:
        return str(int(orig))  # python bools are ints

    try:
        i32orig = int(str(orig))  # don't encode floats as ints
        if -I32_BOUND <= i32orig < I32_BOUND:
            return str(i32orig)
    except (ValueError, TypeError):
        pass

    rv = int.from_bytes(sha256(str(orig).encode()).digest(), "big")

    return str(rv)


async def setup_with_steward():
    print("indy demo")
    print("Step 1")
    progress = 0
    print("Opening Pool Legder {}".format(pool_["name"]))
    pool_["genesis_txn_path"] = "pool1.txn"
    pool_["config"] = json.dumps({"genesis_txn": str(pool_["genesis_txn_path"])})

    print(pool_)

    progress = 10
    emit("process_update", {"progress": progress}, namespace="/")

    print("connecting to pool")
    await pool.set_protocol_version(2)

    try:
        await pool.create_pool_ledger_config(pool_["name"], pool_["config"])
    except IndyError as err:
        if err.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_["handle"] = await pool.open_pool_ledger(pool_["name"], None)
    print(pool_["handle"])

    print("Step 2: Config the Stewards")
    if steward["pool"] == None or steward["pool"] != pool_["handle"]:
        steward["pool"] = pool_["handle"]

    progress = 50
    emit("process_update", {"progress": progress}, namespace="/")

    await create_wallet(steward)

    print('"Sovrin Steward" -> Create and store in Wallet DID from seed')
    steward["did_info"] = json.dumps({"seed": steward["seed"]})
    steward["did"], steward["key"] = await did.create_and_store_my_did(
        steward["wallet"], steward["did_info"]
    )
    print("\n=====================================================================")
    if government["pool"] != steward["pool"]:
        government["pool"] = steward["pool"]
    await getting_verinym(steward, government)
    if verismart["pool"] != steward["pool"]:
        verismart["pool"] = steward["pool"]
    await getting_verinym(steward, verismart)
    progress = 100
    emit("process_update", {"progress": progress}, namespace="/")


async def create_wallet_for_anyone(wallet):
    progress = 0
    emit("any_wallet_update", {"progress": 10}, namespace="/")
    if wallet["pool"] != steward["pool"]:
        wallet["pool"] = steward["pool"]
    await create_wallet(wallet)
    (wallet["did"], wallet["key"]) = await did.create_and_store_my_did(
        wallet["wallet"], "{}"
    )
    wallet["consent"] = True
    emit("any_wallet_update", {"progress": 100}, namespace="/")


async def create_schema(schema, issuer):
    flag = False
    issuer_wallet = {}
    emit("any_schema_update", {"progress": 10}, namespace="/")
    if issuer in installed_wallets.keys():
        issuer_wallet = installed_wallets[issuer]
        flag = True
    else:
        issuer_wallet = government

    (
        issuer_wallet["{}_schema_id".format(schema["name"])],
        issuer_wallet["{}_schema".format(schema["name"])],
    ) = await anoncreds.issuer_create_schema(
        issuer_wallet["did"],
        schema["name"],
        schema["version"],
        json.dumps(schema["attributes"]),
    )
    emit("any_schema_update", {"progress": 30}, namespace="/")

    example_schema_id = issuer_wallet["{}_schema_id".format(schema["name"])]
    installed_schema_ids["{}_schema_id".format(schema["name"])] = example_schema_id
    print(
        '"{}" -> Send "{}" Schema to Ledger'.format(
            issuer_wallet["name"], schema["name"]
        )
    )
    emit("any_schema_update", {"progress": 70}, namespace="/")

    await send_schema(
        issuer_wallet["pool"],
        issuer_wallet["wallet"],
        issuer_wallet["did"],
        issuer_wallet["{}_schema".format(schema["name"])],
    )

    if flag:
        installed_wallets[issuer] = issuer_wallet

    emit("any_schema_update", {"progress": 100}, namespace="/")


async def create_cred_def_function(cred_def, issuer, schema_name):
    emit("any_cred_def", {"progress": 10}, namespace="/")
    print(installed_schema_ids)
    issuer_wallet = installed_wallets[issuer] if issuer else verismart
    schema_id = installed_schema_ids["{}_schema_id".format(schema_name)]
    print(
        '"{}" -> Get from Ledger "{}" Schema'.format(issuer_wallet["name"], schema_name)
    )
    (
        issuer_wallet["{}_schema_id".format(schema_name)],
        issuer_wallet["{}_schema".format(schema_name)],
    ) = await get_schema(issuer_wallet["pool"], issuer_wallet["did"], schema_id)

    (
        issuer_wallet["{}_cred_def_id".format(schema_name)],
        issuer_wallet["{}_cred_def".format(schema_name)],
    ) = await anoncreds.issuer_create_and_store_credential_def(
        issuer_wallet["wallet"],
        issuer_wallet["did"],
        issuer_wallet["{}_schema".format(schema_name)],
        cred_def["tag"],
        cred_def["type"],
        json.dumps(cred_def["config"]),
    )
    emit("any_cred_def", {"progress": 40}, namespace="/")
    print(
        '"{}" -> Send  "{}" Credential Definition to Ledger'.format(
            schema_id, schema_name
        )
    )
    await send_cred_def(
        issuer_wallet["pool"],
        issuer_wallet["wallet"],
        issuer_wallet["did"],
        issuer_wallet["{}_cred_def".format(schema_name)],
    )
    emit("any_cred_def", {"progress": 100}, namespace="/")


async def get_vcs_function(from_, to, schema_name, schema_values):
    print("\n=====================================================================")
    from_wallet, to_wallet = installed_wallets[from_], installed_wallets[to]
    emit("process_update", {"progress": 10}, namespace="/")

    print(
        "== Getting {} with {} to {} - Getting {} Credential ==".format(
            schema_name, from_wallet["name"], to_wallet["name"], schema_name
        )
    )
    from_wallet[
        "{}_cred_offer".format(schema_name)
    ] = await anoncreds.issuer_create_credential_offer(
        from_wallet["wallet"], from_wallet["{}_cred_def_id".format(schema_name)]
    )
    print(
        '"{}" -> Create "{}" Credential Offer for {}'.format(
            to_wallet["name"], schema_name, from_wallet["name"]
        )
    )
    print(
        '"{}" -> Send "{}" Credential Offer to {}'.format(
            from_wallet["name"], schema_name, to_wallet["name"]
        )
    )

    to_wallet["{}_cred_offer".format(schema_name)] = from_wallet[
        "{}_cred_offer".format(schema_name)
    ]
    cred_offer_object = json.loads(to_wallet["{}_cred_offer".format(schema_name)])
    print(cred_offer_object)
    to_wallet["{}_schema_id".format(schema_name)] = cred_offer_object["schema_id"]
    to_wallet["{}_cred_def_id".format(schema_name)] = cred_offer_object["cred_def_id"]

    print(
        '"{}" -> Create and store "{}" Master Secret in Wallet'.format(
            to_wallet["name"], to_wallet["name"]
        )
    )

    to_wallet["master_secret_id"] = await anoncreds.prover_create_master_secret(
        to_wallet["wallet"], None
    )
    emit("process_update", {"progress": 30}, namespace="/")

    print('"{}" -> Get "{} Transcript" Credential Definition from Ledger')
    (
        to_wallet["legder_{}_cred_def_id".format(schema_name)],
        to_wallet["ledger_{}_cred_def".format(schema_name)],
    ) = await get_cred_def(
        to_wallet["pool"],
        to_wallet["did"],
        to_wallet["{}_cred_def_id".format(schema_name)],
    )
    emit(
        "ledger_cred_def",
        {
            "progress": 100,
            "cred_def": to_wallet["legder_{}_cred_def_id".format(schema_name)],
        },
        namespace="/",
    )
    print(
        '"{}" -> Create "{}" Credential Request for {}'.format(
            to_wallet["name"], schema_name, to_wallet["name"]
        )
    )
    emit("process_update", {"progress": 50}, namespace="/")

    (
        to_wallet["{}_cred_request".format(schema_name)],
        to_wallet["{}_cred_request_metadata".format(schema_name)],
    ) = await anoncreds.prover_create_credential_req(
        to_wallet["wallet"],
        to_wallet["did"],
        to_wallet["{}_cred_offer".format(schema_name)],
        to_wallet["ledger_{}_cred_def".format(schema_name)],
        to_wallet["master_secret_id"],
    )
    print(
        '"{}" -> Send "{}" Credential Request to {}'.format(
            to_wallet["name"], schema_name, from_wallet["name"]
        )
    )
    from_wallet["{}_cred_request".format(schema_name)] = to_wallet[
        "{}_cred_request".format(schema_name)
    ]

    dic_values = {}
    for i in schema_values.keys():
        dic_values[i] = {"raw": schema_values[i], "encoded": encode(schema_values[i])}

    print("\n", "\n", dic_values, "\n", "\n")
    to_wallet["{}_cred_values".format(schema_name)] = json.dumps(dic_values)

    from_wallet["{}_{}_cred_values".format(to_wallet["name"], schema_name)] = to_wallet[
        "{}_cred_values".format(schema_name)
    ]
    print(
        '"{}" -> Create "{}" Credential for {}'.format(
            from_wallet["name"], schema_name, to_wallet["name"]
        )
    )
    (
        from_wallet["{}_cred".format(schema_name)],
        _,
        _,
    ) = await anoncreds.issuer_create_credential(
        from_wallet["wallet"],
        from_wallet["{}_cred_offer".format(schema_name)],
        from_wallet["{}_cred_request".format(schema_name)],
        from_wallet["{}_{}_cred_values".format(to_wallet["name"], schema_name)],
        None,
        None,
    )
    print(
        '"{}" -> Send "{}" Credential to {}'.format(
            from_wallet["name"],
            schema_name,
            to_wallet["name"],
        )
    )
    to_wallet["{}_cred".format(schema_name)] = from_wallet[
        "{}_cred".format(schema_name)
    ]
    emit("process_update", {"progress": 70}, namespace="/")

    print(
        '"{}" -> Store "{}" Credential from {}'.format(
            to_wallet["name"], schema_name, from_wallet["name"]
        )
    )
    _, to_wallet["{}_cred_def".format(schema_name)] = await get_cred_def(
        to_wallet["pool"],
        to_wallet["did"],
        to_wallet["{}_cred_def_id".format(schema_name)],
    )

    await anoncreds.prover_store_credential(
        to_wallet["wallet"],
        None,
        to_wallet["{}_cred_request_metadata".format(schema_name)],
        to_wallet["{}_cred".format(schema_name)],
        to_wallet["{}_cred_def".format(schema_name)],
        None,
    )
    installed_wallets[from_], installed_wallets[to] = from_wallet, to_wallet
    emit("process_update", {"progress": 100}, namespace="/")
    emit(
        "process_data",
        {"data": to_wallet["{}_cred_def".format(schema_name)]},
        namespace="/",
    )

    print("\n=====================================================================")


async def verify_a_given_vc(from_, to, schema_name, restrictions):
    print("\n=====================================================================")
    emit("process_update", {"progress": 0}, namespace="/")

    print("== Time to verify - {} proving ==".format(schema_name))
    try:
        from_wallet, to_wallet = installed_wallets[from_], installed_wallets[to]
    except KeyError:
        print("sorry the wallet is not installed")
        return
    nonce = await anoncreds.generate_nonce()
    requested_attributes, requested_predicates = {}, {}
    current_schema = installed_schemas[schema_name]
    predicates = [i["name"] for i in restrictions]
    print(predicates, restrictions)
    emit("process_update", {"progress": 10}, namespace="/")

    for i, v in enumerate(current_schema["attributes"]):
        if v in predicates:
            continue

        if "name" in v or "phone" in v:
            requested_attributes["attr{}_referent".format(i)] = {"name": v}
        else:
            requested_attributes["attr{}_referent".format(i)] = {
                "name": v,
                "restrictions": [
                    {"cred_def_id": from_wallet["{}_cred_def_id".format(schema_name)]}
                ],
            }
    if len(restrictions) > 0:
        for i, v in enumerate(restrictions):
            requested_predicates["predicate{}_referent".format(i)] = {
                "name": v["name"],
                "p_type": v["p_type"],
                "p_value": 2,
                "restrictions": [
                    {"cred_def_id": from_wallet["{}_cred_def_id".format(schema_name)]}
                ],
            }
    emit("process_update", {"progress": 20}, namespace="/")

    print(requested_attributes, requested_predicates)

    credential_proof_request_dict = {
        "nonce": nonce,
        "name": "{}_proof".format(schema_name),
        "version": "0.1",
        "requested_attributes": requested_attributes,
        "requested_predicates": requested_predicates,
    }

    from_wallet["{}_proof_request".format(schema_name)] = json.dumps(
        {
            "nonce": nonce,
            "name": "{}_proof".format(schema_name),
            "version": "0.1",
            "requested_attributes": requested_attributes,
            "requested_predicates": requested_predicates,
        }
    )
    emit("process_update", {"progress": 30}, namespace="/")

    emit(
        "values_needed_for_verification",
        {"values needed": from_wallet["{}_proof_request".format(schema_name)]},
        namespace="/",
    )

    print(
        '"{}" -> Send "{}" Proof Request to {}'.format(
            from_wallet["name"], schema_name, to_wallet["name"]
        )
    )

    to_wallet["{}_proof_request".format(schema_name)] = from_wallet[
        "{}_proof_request".format(schema_name)
    ]
    print(
        '"{}" -> Get credentials for "{}" Proof Request'.format(
            to_wallet["name"], schema_name
        )
    )
    print("\n", to_wallet["{}_proof_request".format(schema_name)])
    search_proof_request = await anoncreds.prover_search_credentials_for_proof_req(
        to_wallet["wallet"], to_wallet["{}_proof_request".format(schema_name)], None
    )
    print(search_proof_request)
    creds_for_attrs, creds_for_predicates = [], []

    for i in credential_proof_request_dict["requested_attributes"].keys():
        number = i.split("_")[0][-1]
        print("cred_for_attr{}".format(number), print(i))
        creds_for_attrs.append(
            {
                "cred_for_attr{}".format(number): await get_credential_for_referent(
                    search_proof_request, "attr{}_referent".format(number)
                )
            }
        )

    emit("process_update", {"progress": 50}, namespace="/")

    for i in credential_proof_request_dict["requested_predicates"].keys():
        number = i.split("_")[0][-1]
        creds_for_predicates.append(
            {
                "cred_for_predicate{}".format(
                    number
                ): await get_credential_for_referent(
                    search_proof_request, "predicate{}_referent".format(number)
                )
            }
        )

    print(creds_for_attrs, creds_for_predicates)

    to_wallet["creds_for_{}_proof".format(schema_name)] = {}
    temp_dict = {}
    for i in creds_for_attrs:
        number = list(i.keys())[0][-1]
        key = list(i.keys())[0]
        temp_dict.update({i[key]["referent"]: i[key]})
    to_wallet["creds_for_{}_proof".format(schema_name)].update(temp_dict)
    temp_dict = {}
    for i in creds_for_predicates:
        number, key = list(i.keys())[0][-1], list(i.keys())[0]
        temp_dict.update({i[key]["referent"]: i[key]})
    to_wallet["creds_for_{}_proof".format(schema_name)].update(temp_dict)

    print("\n", "\n", to_wallet["creds_for_{}_proof".format(schema_name)])
    print(
        "loldsdsdasdfjowfhweoghfweoifjwo",
        "\n",
        to_wallet["creds_for_{}_proof".format(schema_name)],
        "\n",
    )
    await anoncreds.prover_close_credentials_search_for_proof_req(search_proof_request)

    (
        to_wallet["schemas"],
        to_wallet["cred_defs"],
        to_wallet["revoc_states"],
    ) = await prover_get_entities_from_ledger(
        to_wallet["pool"],
        to_wallet["did"],
        to_wallet["creds_for_{}_proof".format(schema_name)],
        to_wallet["name"],
    )
    emit("process_update", {"progress": 60}, namespace="/")

    print('"{}" -> Create "{}" Proof'.format(to_wallet["name"], schema_name))
    from_wallet, to_wallet = installed_wallets[from_], installed_wallets[to]
    print(creds_for_attrs, creds_for_predicates)

    self_attested_attrs, creds_requested_attributes, creds_requested_predicates = (
        {},
        {},
        {},
    )
    seen = []
    for i in credential_proof_request_dict["requested_attributes"].keys():
        number = i.split("_")[0][-1]
        print(number)
        print(i)
        dict_obj = credential_proof_request_dict["requested_attributes"]
        attr_name = dict_obj[i]["name"]
        if "first_name" == attr_name:
            self_attested_attrs.update({i: "rudransh"})
            seen.append(number)

        elif "last_name" == attr_name:
            self_attested_attrs.update({i: "sharma"})
            seen.append(number)

        else:
            for j in creds_for_attrs:
                number = list(j.keys())[0][-1]
                print(j, i, "\n", number)
                if number in seen:
                    continue
                else:
                    creds_requested_attributes.update(
                        {
                            "attr{}_referent".format(number): {
                                "cred_id": j[list(j.keys())[0]]["referent"],
                                "revealed": to_wallet["consent"],
                            }
                        }
                    )

    print(
        "\n",
        "\n",
        "\n",
        creds_requested_attributes,
        "\n",
        "\n",
        "\n",
        self_attested_attrs,
    )
    seen = []
    for i in credential_proof_request_dict["requested_predicates"].keys():
        number = i.split("_")[0][-1]
        print(number)
        print(i)
        dict_obj = credential_proof_request_dict["requested_predicates"]
        pred_name = dict_obj[i]["name"]
        for j in creds_for_predicates:
            number = list(j.keys())[0][-1]
            if number in seen:
                continue
            else:
                creds_requested_predicates.update(
                    {
                        "predicate{}_referent".format(number): {
                            "cred_id": j[list(j.keys())[0]]["referent"],
                        }
                    }
                )
    print("\n", creds_requested_predicates)
    emit("process_update", {"progress": 70}, namespace="/")

    to_wallet["{}_requested_creds".format(schema_name)] = json.dumps(
        {
            "self_attested_attributes": self_attested_attrs,
            "requested_attributes": creds_requested_attributes,
            "requested_predicates": creds_requested_predicates,
        }
    )

    to_wallet["{}_proof".format(schema_name)] = await anoncreds.prover_create_proof(
        to_wallet["wallet"],
        to_wallet["{}_proof_request".format(schema_name)],
        to_wallet["{}_requested_creds".format(schema_name)],
        to_wallet["master_secret_id"],
        to_wallet["schemas"],
        to_wallet["cred_defs"],
        to_wallet["revoc_states"],
    )
    print(
        '"{}" -> Send "{}" Proof to {}'.format(
            to_wallet["name"], schema_name, from_wallet["name"]
        )
    )
    from_wallet["{}_proof".format(schema_name)] = to_wallet[
        "{}_proof".format(schema_name)
    ]
    proof_object = json.loads(from_wallet["{}_proof".format(schema_name)])

    (
        from_wallet["schemas_for_{}".format(schema_name)],
        from_wallet["cred_defs_for_{}".format(schema_name)],
        from_wallet["revoc_ref_defs_for_{}".format(schema_name)],
        from_wallet["revoc_regs_for_{}".format(schema_name)],
    ) = await verifier_get_entities_from_ledger(
        to_wallet["pool"],
        to_wallet["did"],
        proof_object["identifiers"],
        to_wallet["name"],
    )
    print("\n", "\n", proof_object)
    print(
        '"{}" -> Verify "{}" Proof from {}'.format(
            from_wallet["name"], schema_name, to_wallet["name"]
        )
    )
    # assert (
    #     "engg"
    #     == proof_object["requested_proof"]["revealed_attrs"]["attr2_referent"]["raw"]
    # )

    # assert (
    #     "rudransh"
    #     == proof_object["requested_proof"]["self_attested_attrs"]["attr0_referent"]
    # )
    # assert (
    #     "sharma"
    #     == proof_object["requested_proof"]["self_attested_attrs"]["attr1_referent"]
    # )
    emit("process_update", {"progress": 80}, namespace="/")

    x = await anoncreds.verifier_verify_proof(
        from_wallet["{}_proof_request".format(schema_name)],
        from_wallet["{}_proof".format(schema_name)],
        from_wallet["schemas_for_{}".format(schema_name)],
        from_wallet["cred_defs_for_{}".format(schema_name)],
        from_wallet["revoc_ref_defs_for_{}".format(schema_name)],
        from_wallet["revoc_regs_for_{}".format(schema_name)],
    )
    print("\n=====================================================================", x)

    print(
        from_wallet["{}_proof_request".format(schema_name)],
        "\n",
        "\n",
        "\n",
        from_wallet["{}_proof".format(schema_name)],
        "\n",
        "\n",
        "\n",
        from_wallet["schemas_for_{}".format(schema_name)],
        "\n",
        "\n",
        "\n",
        from_wallet["cred_defs_for_{}".format(schema_name)],
        "\n",
        "\n",
        "\n",
        from_wallet["revoc_ref_defs_for_{}".format(schema_name)],
        "\n",
        "\n",
        "\n",
        from_wallet["revoc_regs_for_{}".format(schema_name)],
        "\n",
        "\n",
        "\n",
    )
    from_wallet, to_wallet = installed_wallets[from_], installed_wallets[to]
    emit("process_update", {"progress": 100}, namespace="/")
    emit("process_data", {"proof_truth": x}, namespace="/")


@socketio.on("start_process", namespace="/")
def create_steward_wallet():
    loop.run_until_complete(setup_with_steward())
    return jsonify({"message": "Steward created successfully"})


@socketio.on("onboard_any", namespace="/")
def onboard_any(data):
    print("\n================================================================")
    print(data, type(data))
    name, key = data["data"]["name"], data["data"]["password"]
    wallet = {
        "name": name,
        "wallet_config": json.dumps({"id": name + "_wallet"}),
        "wallet_credentials": json.dumps({"key": key}),
        "pool": pool_["handle"],
        "role": "ENDORSER",
    }
    loop.run_until_complete(create_wallet_for_anyone(wallet))
    installed_wallets[name] = wallet
    return jsonify({"message": "wallet for" + name + " is done"})


@socketio.on("create_schema_any", namespace="/")
def create_schema_any(data):
    schema_name, schema_atributes = data["name"], data["atributes"]
    print(schema_name, schema_atributes)
    issuer = data["issuer"] if data["issuer"] else None
    example_schema = {
        "name": schema_name,
        "version": "0.2",
        "attributes": schema_atributes,
    }
    installed_schemas[schema_name] = example_schema
    loop.run_until_complete(create_schema(example_schema, issuer))
    return jsonify({"message": "schema for" + schema_name + " is done"})


@socketio.on("create_credDef_any", namespace="/")
def create_credDef_any(data):
    print("\n=====================================================================")
    issuer, schema_name = (
        data["issuer"],
        data["schema_name"],
    )
    print("=== Verismart Credential Definition Setup ==")
    cred_def = {
        "tag": "TAG1",
        "type": "CL",
        "config": {"support_revocation": False},
    }
    loop.run_until_complete(create_cred_def_function(cred_def, issuer, schema_name))
    return jsonify({"message": "done successfully"})


@socketio.on("get_vcs", namespace="/")
def get_vcs(data):
    from_, to, schema_name, schema_values = (
        data["from"],
        data["to"],
        data["schema_name"],
        data["schema_values"],
    )
    loop.run_until_complete(get_vcs_function(from_, to, schema_name, schema_values))


@socketio.on("verify_vcs_admin", namespace="/")
def verify_vcs(data):
    print(data, data.keys())
    from_, to, schema_name, restrictions = (
        data["from"],
        data["to"],
        data["schema_name"],
        data["restrictions"],
    )
    print(restrictions, data.keys(), data)
    loop.run_until_complete(verify_a_given_vc(from_, to, schema_name, restrictions))


@socketio.on("get_wallets_list", namespace="/")
def get_wallets_all():
    emit("all_wallets_list", {"wallets": installed_wallets}, namespace="/")
    emit("process_update", {"progress": 100}, namespace="/")
    emit("process_data", {"data": installed_wallets}, namespace="/")


@socketio.on("get_schema_list", namespace="/")
def get_all_schemas():
    emit("all_schemas", {"schemas": installed_schemas}, namespace="/")
    emit("process_update", {"progress": 100}, namespace="/")
    emit("process_data", {"data": installed_schemas}, namespace="/")


@socketio.on("get_all_shema_ids", namespace="/")
def get_all_shema_ids():
    emit("all_shema_ids", {"shema_ids": installed_schema_ids}, namespace="/")
    emit("process_update", {"progress": 100}, namespace="/")
    emit("process_data", {"data": installed_schema_ids}, namespace="/")


@socketio.on("get_did", namespace="/")
def get_did(name):
    wallet = installed_wallets[name]
    emit("certain_did", {"did": wallet["did"]}, namespace="/")
    emit("process_update", {"progress": 100}, namespace="/")
    emit("process_data", {"did": wallet["did"]}, namespace="/")


async def close_ledger():
    print('"Sovrin Steward" -> Close and Delete wallet')
    await wallet.close_wallet(steward["wallet"])
    await wallet.delete_wallet(steward["wallet_config"], steward["wallet_credentials"])

    print('"Government" -> Close and Delete wallet')
    await wallet.close_wallet(government["wallet"])
    await wallet.delete_wallet(
        government["wallet_config"], government["wallet_credentials"]
    )

    print('"Verismart" -> Close and Delete wallet')
    await wallet.close_wallet(verismart["wallet"])
    await wallet.delete_wallet(
        verismart["wallet_config"], verismart["wallet_credentials"]
    )

    for i in installed_wallets.keys():
        await wallet.close_wallet(installed_wallets[i]["wallet"])
        await wallet.delete_wallet(
            installed_wallets[i]["wallet_config"],
            installed_wallets[i]["wallet_credentials"],
        )
    await wallet.close_wallet(installed_wallets["rudransh"]["wallet"])
    await wallet.delete_wallet(
        installed_wallets["rudransh"]["wallet_config"],
        installed_wallets["rudransh"]["wallet_credentials"],
    )
    print("Close and Delete pool")
    await pool.close_pool_ledger(pool_["handle"])
    await pool.delete_pool_ledger_config(pool_["name"])


@socketio.on("stop", namespace="/")
def stop():
    loop.run_until_complete(close_ledger())


@socketio.on("get_wallet", namespace="/")
def get_wallet(data):
    name = data["name"]
    to_wallet = installed_wallets[name]
    print(to_wallet.keys())

    print(
        json.dumps(
            json.loads(json.dumps(to_wallet, separators=(",", ":"))),
            separators=(",", ":"),
        )
    )
    emit("process_update", {"progress": 100}, namespace="/")
    emit(
        "process_data",
        {
            "data": json.dumps(
                json.loads(json.dumps(to_wallet, separators=(",", ":"))),
                separators=(",", ":"),
            )
        },
        namespace="/",
    )


@socketio.on("store_consent", namespace="/")
def store_consent(consent, name):
    wallet = installed_wallets[name]
    wallet["consent"] = consent
    emit(
        "set_consent",
        {"message": "Your consent has been set to{}".format(consent)},
        namespace="/",
    )


@socketio.on("login", namespace="/")
def login(data):
    name, password = data["name"], data["password"]
    print(government["wallet_credentials"], type(government["wallet_credentials"]))
    wallet = json.loads(government["wallet_credentials"])["key"]
    print(wallet)

    if name in installed_wallets.keys():
        key = json.loads(active_wallet["wallet_credentials"])["key"]
        if key != password:
            emit(
                "login_failure",
                {"message": "sorry you have the wrong key"},
                namespace="/",
            )
            return
        active_wallet = installed_wallets[name]
        emit("login_success", {"name": name, "wallet": active_wallet}, namespace="/")
    else:
        emit(
            "login_failure",
            {"message": "sorry you would need to register"},
            namespace="/",
        )


@socketio.on("register_for_user", namespace="/")
def register_for_user(data):
    print("\n================================================================")
    name, key = data["name"], data["password"]
    wallet = {
        "name": name,
        "wallet_config": json.dumps({"id": name + "_wallet"}),
        "wallet_credentials": json.dumps({"key": key}),
        "pool": pool_["handle"],
    }
    loop.run_until_complete(create_wallet_for_anyone(wallet))
    installed_wallets[name] = wallet
    emit(
        "reg_success",
        {"message": "Reg for {} is done successfully".format(name), "wallet": wallet},
        namespace="/",
    )
    return jsonify({"message": "wallet for" + name + " is done"})


@socketio.on("register_for_orgs", namespace="/")
def register_for_orgs(data):
    print("\n================================================================")
    name, key = data["name"], data["password"]
    wallet = {
        "name": name,
        "wallet_config": json.dumps({"id": name + "_wallet"}),
        "wallet_credentials": json.dumps({"key": key}),
        "pool": pool_["handle"],
        "role": "ENDORSER",
    }
    loop.run_until_complete(create_wallet_for_anyone(wallet))
    installed_wallets[name] = wallet
    emit(
        "reg_success",
        {"message": "Reg for {} is done successfully".format(name), "wallet": wallet},
        namespace="/",
    )
    return jsonify({"message": "wallet for" + name + " is done"})


@socketio.on("run_network", namespace="/")
def run_network():
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/tests/network-setups/fabric/dev && make start-interop-local PROFILE='2-nodes'",
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit("network_started", {"message": "the network has been started successfully"})


@socketio.on("run_relay_1", namespace="/")
def run_relay_1():
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/relay && RELAY_CONFIG=config/Fabric_Relay.toml cargo run --bin server",
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "relay_1_started",
        {
            "message": "the relay for network 1 has been started has been started successfully"
        },
    )


@socketio.on("run_relay_2", namespace="/")
def run_relay_2():
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/relay && RELAY_CONFIG=config/Fabric_Relay2.toml cargo run --bin server",
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "relay_2_started",
        {
            "message": "the relay for network 2 has been started has been started successfully"
        },
    )


@socketio.on("run_driver_1", namespace="/")
def run_driver_1():
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/drivers/fabric-driver && npm run dev",
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "driver_1_started",
        {
            "message": "the driver for network 1 has been started has been started successfully"
        },
    )


@socketio.on("run_driver_2", namespace="/")
def run_driver_2():
    commands = [
        """cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/drivers/fabric-driver && 
        CONNECTION_PROFILE=Users/rudranshsharma/dev/weaver-dlt-interoperability/tests/network-setups/fabric/shared/network2/peerOrganizations/org1.network2.com/connection-org1.json NETWORK_NAME=network2 RELAY_ENDPOINT=localhost:9083 DRIVER_ENDPOINT=localhost:9095 npm run dev
        """,
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "driver_2_started",
        {
            "message": "the driver for network 2 has been started has been started successfully"
        },
    )


@socketio.on("run_iin_1", namespace="/")
def run_iin_1():
    commands = [
        """cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/identity-management/iin-agent && npm run dev""",
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "iin_1_started",
        {
            "message": "the iin_agent for network 1 org 1 has been started has been started successfully"
        },
    )


@socketio.on("run_iin_2", namespace="/")
def run_iin_2():
    commands = [
        """cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/identity-management/iin-agent && IIN_AGENT_ENDPOINT=localhost:9510 MEMBER_ID=Org2MSP CONFIG_PATH=./src/fabric-ledger/config-n1-org2.json npm run dev """,
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "iin_2_started",
        {
            "message": "the iin_agent for network 1 org 2 has been started has been started successfully"
        },
    )


@socketio.on("run_iin_3", namespace="/")
def run_iin_3():
    commands = [
        """cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/identity-management/iin-agent && IIN_AGENT_ENDPOINT=localhost:9501 SECURITY_DOMAIN=network2 CONFIG_PATH=./src/fabric-ledger/config-n2-org1.json npm run dev """,
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "iin_3_started",
        {
            "message": "the iin_agent for network 2 org 1 has been started has been started successfully"
        },
    )


@socketio.on("run_iin_4", namespace="/")
def run_iin_4():
    commands = [
        """cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/core/identity-management/iin-agent && IIN_AGENT_ENDPOINT=localhost:9511 MEMBER_ID=Org2MSP SECURITY_DOMAIN=network2 CONFIG_PATH=./src/fabric-ledger/config-n2-org2.json npm run dev""",
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "iin_4_started",
        {
            "message": "the iin_agent for network 2 org 2 has been started has been started successfully"
        },
    )


@socketio.on("ledger_init", namespace="/")
def run_ledger_init():
    commands = [
        """cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabirc/fabric-cli && 
            ./bin/fabric-cli env set-file ./.env &&
            ./bin/fabric-cli configure all network1 network2 --num-orgs=2 &&
            ./bin/fabric-cli configure membership --local-network=network1 --target-network=network2 --iin-agent-endpoint=localhost:9500 &&
            ./bin/fabric-cli configure membership --local-network=network2 --target-network=network1 --iin-agent-endpoint=localhost:9501
        """,
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "iin_4_started",
        {
            "message": "the iin_agent for network 2 org 2 has been started has been started successfully"
        },
    )


@socketio.on("interop", namespace="/")
def run_interop_flow():
    commands = [
        """
        cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabirc/fabric-cli && 
        ./bin/fabric-cli interop --local-network=network1 --requesting-org=Org1MSP localhost:9083/network2/mychannel:simplestate:Read:Arcturus
        ./bin/fabric-cli interop --local-network=network2 --requesting-org=Org1MSP localhost:9080/network1/mychannel:simplestate:Read:a
        """
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "interop_completed",
        {"message": "the interop flow has been started successfully"},
    )


@socketio.on("add_values_ledger_1", namespace="/")
def add_values_ledger_1(data):
    name, schema_name = data["name"], data["schema_name"]
    if name not in installed_wallets.keys():
        emit(
            "add_values_faliure_1",
            {
                "name": name,
                "message": "sorry the wallet with the given name has not been registered",
            },
            namespace="/",
        )
        return
    to_wallet = installed_wallets[name]
    if "{}_cred".format(schema_name) not in to_wallet.keys():
        emit(
            "add_values_faliure_1",
            {
                "name": name,
                "message": "sorry the wallet with the given name does not have the given credentials",
            },
            namespace="/",
        )
        return
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabric/fabric-cli",
        "ls",
        """./bin/fabric-cli chaincode invoke --local-network=network1 mychannel simplestate create '["{}", "[{}]"]' """.format(
            name, str(to_wallet["{}_cred_values".format(schema_name)]).replace('"', "'")
        ),
    ]

    res = subprocess.check_output(" && ".join(commands), shell=True)
    print(res.decode())
    emit(
        "add_value_success_1",
        {
            "message": "Successfully wrote {} to the ledger1".format(
                json.dumps(to_wallet["{}_cred".format(schema_name)])
            ),
            "value": to_wallet["{}_cred".format(schema_name)],
        },
    )
    emit("process_update", {"progress": 100}, namespace="/")
    emit(
        "process_data",
        {"value": res.decode()},
        namespace="/",
    )
    return True


socketio.on("add_value_ledger_2", namespace="/")


def add_value_ledger_2(data):
    name, schema_name = data["name"], data["schema_name"]
    if name not in installed_wallets.keys():
        emit(
            "add_values_faliure_2",
            {
                "name": name,
                "message": "sorry the wallet with the given name has not been registered",
            },
            namespace="/",
        )
        return
    to_wallet = installed_wallets[name]
    if "{}_cred".format(schema_name) not in to_wallet.keys():
        emit(
            "add_values_faliure_2",
            {
                "name": name,
                "message": "sorry the wallet with the given name does not have the given credentials",
            },
            namespace="/",
        )
        return
    print(to_wallet)
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabric/fabric-cli",
        "ls",
        """./bin/fabric-cli chaincode invoke --local-network=network2 mychannel simplestate create '["{}", "[{}]"]' """.format(
            name, str(to_wallet["{}_cred_values".format(schema_name)]).replace('"', "'")
        ),
    ]

    res = subprocess.check_output(" && ".join(commands), shell=True)
    print(res.decode())
    emit(
        "add_value_success_2",
        {
            "message": "Successfully wrote {} to the ledger1".format(
                json.dumps(to_wallet["{}_cred".format(schema_name)])
            ),
            "value": to_wallet["{}_cred".format(schema_name)],
        },
    )

    return True


@socketio.on("interop_query", namespace="/")
def interop_query(data):
    name, schema_name = data["name"], data["schema_name"]
    if name not in installed_wallets.keys():
        emit(
            "interop_query_failure",
            {
                "name": name,
                "message": "sorry the wallet with the given name has not been registered",
            },
            namespace="/",
        )
        return
    to_wallet = installed_wallets[name]
    if "{}_cred".format(schema_name) not in to_wallet.keys():
        emit(
            "interop_query_failure",
            {
                "name": name,
                "message": "sorry the wallet with the given name does not have the given credentials",
            },
            namespace="/",
        )
        return

    with open(JSON_FILE_LOCATION, "r+") as f:
        data = json.load(f)
        print(data["simplestate"]["Create"]["args"])
        data["simplestate"]["Create"]["args"][0] = name
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()

    with open(JSON_FILE_LOCATION, "r+") as f:
        data = json.load(f)
        print(data)
    print(
        "./bin/fabric-cli interop --local-network=network2 --requesting-org=Org1MSP localhost:9080/network1/mychannel:simplestate:Read:{}".format(
            name
        ),
    )
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabric/fabric-cli",
        "./bin/fabric-cli interop --local-network=network2 --requesting-org=Org1MSP localhost:9080/network1/mychannel:simplestate:Read:{}".format(
            name
        ),
    ]
    res = subprocess.check_output(" && ".join(commands), shell=True)
    print(res.decode())
    emit(
        "interop_query_success",
        {
            "message": "Successfully wrote {} to the ledger1".format(
                json.dumps(to_wallet["{}_cred".format(schema_name)])
            ),
            "value": to_wallet["{}_cred".format(schema_name)],
        },
    )
    emit("process_update", {"progress": 100}, namespace="/")
    emit(
        "process_data",
        {"value": res.decode()},
        namespace="/",
    )
    return True


@socketio.on("query_ledger_1", namespace="/")
def query_ledger_1(data):
    name, schema_name = data["name"], data["schema_name"]
    if name not in installed_wallets.keys():
        emit(
            "query_failure_1",
            {
                "name": name,
                "message": "sorry the wallet with the given name has not been registered",
            },
            namespace="/",
        )
        return
    to_wallet = installed_wallets[name]
    if "{}_cred".format(schema_name) not in to_wallet.keys():
        emit(
            "query_failure_1",
            {
                "name": name,
                "message": "sorry the wallet with the given name does not have the given credentials",
            },
            namespace="/",
        )
        return
    commands = [
        "cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabric/fabric-cli",
        "ls",
        "./bin/fabric-cli chaincode query --local-network=network1 mychannel simplestate Read '[{}]'".format(
            name
        ),
    ]
    res = subprocess.check_output(" && ".join(commands), shell=True)
    print(res.decode())
    emit(
        "query_success_1",
        {
            "message": "Successfully read {} from the ledger1".format(
                json.dumps(to_wallet["{}_cred".format(schema_name)])
            ),
            "value": to_wallet["{}_cred".format(schema_name)],
        },
    )
    return True


@socketio.on("query_ledger_2", namespace="/")
def query_ledger_1(data):
    name, schema_name = data["name"], data["schema_name"]
    if name not in installed_wallets.keys():
        emit(
            "query_failure_2",
            {
                "name": name,
                "message": "sorry the wallet with the given name has not been registered",
            },
            namespace="/",
        )
        return
    to_wallet = installed_wallets[name]
    if "{}_cred".format(schema_name) not in to_wallet.keys():
        emit(
            "query_failure_2",
            {
                "name": name,
                "message": "sorry the wallet with the given name does not have the given credentials",
            },
            namespace="/",
        )
        return
    commands = [
        """
        cd /Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabirc/fabric-cli &&
         ./bin/fabric-cli interop --local-network=2 mychannel simplestate Read '[{}]'
        """.format(
            name
        )
    ]
    for command in commands:
        res = subprocess.check_output(command, shell=True)
        print(res.decode())
    emit(
        "query_success_2",
        {
            "message": "Successfully read {} from the ledger1".format(
                json.dumps(to_wallet["{}_cred".format(schema_name)])
            ),
            "value": to_wallet["{}_cred".format(schema_name)],
        },
    )
    return True


@socketio.on("test", namespace="/")
def test():
    import tempfile

    json_ = {
        "schema_id": "TczMZXuBAXnt4E6G1B7V9F:2:My Schema:0.2",
        "cred_def_id": "PyBpo3fLBJpnXdibimfva7:3:CL:469:TAG1",
        "rev_reg_id": "null",
        "values": {
            "first_name": {
                "raw": "rudransh",
                "encoded": "14486988903634647357436999910523906261981012336160519060377662864245474836300",
            },
            "average": {"raw": "5", "encoded": "5"},
            "degree": {
                "raw": "engg",
                "encoded": "99213317897048890561468140062924739696540369918199191627526820267463898595542",
            },
            "last_name": {
                "raw": "sharma",
                "encoded": "91133445827771556794636374489919842303441316350887722379945031888870481819761",
            },
        },
        "signature": {
            "p_credential": {
                "m_2": "107856187727655447101480489890720260026017682921467542366629122277700712654524",
                "a": "38423452752352733163595609907753379492175209684124492785045678228146409248527271688711566910382085944736521600982657421266524313991968411918280102536033194508701871988849714184688886694770088542421283790080631130557153738174945133225871912699740159613685455269418331736892996261967965174095330327413365201647526291361174740578188121479214689202477867471046881013824529721688656120859909169326614918979599379175014406863137856107051114587037236105461446016218973467309547871377599769571879748498361242262463887844898496300085574938327024290229893552555134205788729608555823837813519743066897805086992191215654542629741",
                "e": "259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929689159177520191714230259662699222661",
                "v": "9211685620664130834258809734651489744628457713731861073495120525084632046956114287809710222984220577450993689316533860291589942951893789643336195426103833578337545039504364883115556379832807387840796617066904800680294831969469680649687943785404208480005136935518561526566468108358366604080191845711175753445711536558651255958516057422138175325510480138529455747239017878488224941802125921038458111362581384705826194737345381157889268918691758050211092359332164235614503483910937227198508792469930295073272529514654553312371197015079090852390058584499321067904651592640102166819159567265250290154719259502967332001486852331596046545111647639343573251393917791212383536096938383350261433123433848814414501435416754405623066776298115589568383003490415112864531161129604432633850943278369025202758378116035335406421422134757",
            },
            "r_credential": "null",
        },
        "signature_correctness_proof": {
            "se": "347195486179562269809953828493602399770837705845597389662599310432447141707815067183296347172963432068693714361915709970912444517622307382584686831911202203460008771222981436237674969684481495370444491946649033944325606955362494854366615175560419014462552571161645103799444333019934895832392592693444018751870937169696362195538656356288168075961839319789700075535058413030730974332148425666138481011274834689700277578060155749726895377866824929249153362998079252605580726711715541087446933655604933603330662311969117176720875466784773019000427606555396719037709246498216449903986359093560616186200131200360287552341",
            "c": "14143694100325141590595523650572884265047924531156055673536993029135658409363",
        },
        "rev_reg": "null",
        "witness": "null",
    }

    print(str(json).replace('"', "'"))
    print(json.dumps(json_).replace('"', "'"))

    name = "rudransh"
    commands = (
        """./bin/fabric-cli chaincode invoke --local-network=network1 mychannel simplestate create '["{}", "[{}]"]' """.format(
            name, json.dumps(json_).replace('"', "'")
        ),
    )

    res = subprocess.run(
        commands,
        shell=True,
        capture_output=True,
        text=True,
        cwd="/Users/rudranshsharma/dev/weaver-dlt-interoperability/samples/fabric/fabric-cli",
    )
    print(res.stdout)
    print(res)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8098)
