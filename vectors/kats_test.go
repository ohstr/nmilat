package vectors

// katChecks are the KAT literals of the plan's table (N §4.2, §10.5) as
// they must appear in each committed file. Values are copied, never
// computed: a change in nmilat that moves one turns this red.
var katChecks = map[string][]kat{
	"tlv.json": {
		k("K-TOK-1", "", "decode", "[name=K-TOK-1 (the spec token)]", "error"),
		k("K-TOK-1", "1", "decode", "[name=K-TOK-1 (the spec token)]", "want", "scheme"),
		k("K-TOK-1", "21000", "decode", "[name=K-TOK-1 (the spec token)]", "want", "attestedAmountMillis"),
		k("K-TOK-1", ktok1, "encode", "[name=K-TOK-1 (the spec token)]", "output"),
		k("K-TOK-1 uppercase", "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "decode", "[name=K-TOK-1 uppercase decodes as its lowercase form]", "want", "walletPubkey"),
		k("K-TOK-1 mixed case", "nipcash: bech32 string mixes upper and lower case", "decode", "[name=K-TOK-1 mixed case is refused]", "error"),
		k("TLV 8 absent", "255", "decode", "[name=provenance pair without TLV 8 has no valid provenance]", "want", "scheme"),
	},
	"relay-hash.json": {
		k("K-RH-1", "487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c", "hash", "[id=K-RH-1]", "hash"),
		k("K-RH-2", "1105ab44514b1aa0f20b14313c7c801448daa546a3ef06dcc4cb25b8c4fd7740", "negative", "[id=K-RH-2]", "hash"),
		k("K-RH-3", "69900c591bcd6978a183599c4d21f355da493a4b26e440035c511739562045a7", "negative", "[id=K-RH-3]", "hash"),
		k("K-RH-4", "abe08272a5cca81fdf51ce0774373822ae4aa3130d6148c10c05321588c9b153", "hash", "[id=K-RH-4]", "hash"),
		k("K-RH-5", "eb757e18a18ae11158c67b20196890ac7cc92a12c87f4a6e5e17568f28a3a53f", "hash", "[id=K-RH-5]", "hash"),
		k("K-RH-6", "a6a986b2e479b623370ae8d4b6f27a0ebcdb9de06ddf65357e0b40977c342d0f", "negative", "[id=K-RH-6]", "hash"),
		k("K-RH-7", "5eef6ec81f3de6610fb473f95c9235e979c461d42fe97227059e1a64b20f2edb", "hash", "[id=K-RH-7]", "hash"),
		k("K-RH-8", "454ad3fbd842bc4afd94753d5efc1ee9e6df6a9313ee33291588e21a9232c958", "hash", "[id=K-RH-8]", "hash"),
	},
	"provenance.json": {
		k("K-PAY-1", "cash-mint:v1:satscash:c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5:21000:487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c", "mintPayload", "[name=K-PAY-1]", "payload"),
		k("K-PAY-2", "cash-mint:v1:lokicash:c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5:21000:487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c", "mintPayload", "[name=K-PAY-2 (the label stays cash-mint:v1)]", "payload"),
		k("K-PAY-4", "cash-mint:v1:satscash:c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5:21000:487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c", "mintPayload", "[name=K-PAY-4 (uppercase HRP in a hand-built token)]", "payload"),
		k("K-ZAP-1", "79c69fd2170904248edc898066fce02a7fefa36235f4fb863f4329c99f891b8f", "zapPayload", "[name=K-ZAP-1]", "targetHash"),
		k("K-ZAP-1", "cash-zap:v1:satscash:c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5:5000:487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c:pubkey/2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4:pubkey/fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556:79c69fd2170904248edc898066fce02a7fefa36235f4fb863f4329c99f891b8f:1720000000:0", "zapPayload", "[name=K-ZAP-1]", "payload"),
		k("K-TOK-1", "278d47f6702494ccb7127d9ff80ed049ac324ac6bb30287a20a11c54520cdf23", "specToken", "digest"),
		k("K-TOK-1", "20f2193bb16f948c87d4bd2d90594ff17eae4064d734f487472f2a8e95ed661fa741ab3b154d119c1af8cdaba25710c96748ae5cf179dfc7bcb0254423d4d4b4fa", "specToken", "signature"),
		k("K-TOK-1", "32", "specToken", "header"),
		k("K-TOK-1", "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", "specToken", "minter"),
		k("K-TOK-1", ktok1, "specToken", "token"),
	},
	"request-id.json": {
		k("K-RID-1", "true", "valid", "[id=K-RID-1]", "valid"),
		k("K-RID-1 (31)", "false", "valid", "[id=K-RID-1 (31 chars)]", "valid"),
		k("K-RID-1 (upper)", "false", "valid", "[id=K-RID-1 (uppercase)]", "valid"),
		k("K-DID-1", "1f0d61013abef39098ffb0a7c72008a17099c52aca3d5ee8d6ce8de065db5d37", "derived", "[id=K-DID-1]", "derived"),
		k("K-DID-2", "c4c6d6c4893cca6283c95ea32a0b6bef6be796804e62e21e30113b63c676457e", "derived", "[id=K-DID-2]", "derived"),
	},
	"lookup.json": {
		k("K-DL-1 T+300", "", "deadline", "[deadline=1720000300]", "error"),
		k("K-DL-1 T", "", "deadline", "[deadline=1720000000]", "error"),
		k("K-DL-1 T+301", "nipcash: the call's deadline lies more than H past its arrival", "deadline", "[deadline=1720000301]", "error"),
		k("K-LK-1", "pending", "decideLookup", "[id=K-LK-1]", "status"),
		k("K-LK-1", "1720000001", "decideLookup", "[id=K-LK-1]", "retryAfter"),
		k("K-LK-2", "unknown", "decideLookup", "[id=K-LK-2]", "status"),
		k("K-LK-3", "unknown", "decideLookup", "[id=K-LK-3]", "status"),
		k("K-LK-4", "expired", "decideLookup", "[id=K-LK-4]", "status"),
		k("K-LK-5", "done", "decideLookup", "[id=K-LK-5]", "status"),
		k("K-LK-6", "1720000301", "decideLookup", "[id=K-LK-6]", "retryAfter"),
		k("K-LK-7", "unknown", "decideLookup", "[id=K-LK-7]", "status"),
		k("K-JLK-1 ≤ 300", "1720000301", "decideLookup", "[id=K-JLK-1,now=1720000300]", "retryAfter"),
		k("K-JLK-1 301", "unknown", "decideLookup", "[id=K-JLK-1,now=1720000301]", "status"),
		k("K-JLK-1 660", "unknown", "decideLookup", "[id=K-JLK-1,now=1720000660]", "status"),
		k("K-JLK-1 661", "expired", "decideLookup", "[id=K-JLK-1,now=1720000661]", "status"),
		k("K-JLK-1 +1000", "1720000361", "decideLookup", "[deadline=1720001000]", "retryAfter"),
	},
	"mint-cash.json": {
		k("K-CMT-1", "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd", "commitment", "[id=K-CMT-1]", "commit"),
		k("K-CMT-2", "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b", "commitment", "[id=K-CMT-2]", "commit"),
		k("K-CMT-3", "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925", "commitment", "[id=K-CMT-3]", "commit"),
	},
	"budget-period.json": {
		k("K-BP-1", "1709200800", "start", "[id=K-BP-1]", "start"),
		k("K-BP-2", "1711879200", "start", "[id=K-BP-2]", "start"),
		k("K-BP-3", "1714471200", "start", "[id=K-BP-3]", "start"),
		k("K-BP-4", "1740736800", "start", "[id=K-BP-4]", "start"),
		k("K-BP-5", "1772272800", "start", "[id=K-BP-5]", "start"),
		k("K-BP-6", "1803808800", "start", "[id=K-BP-6]", "start"),
		k("K-BP-7", "1835431200", "start", "[id=K-BP-7]", "start"),
		k("K-BP-8 daily", "1706781600", "start", "[renewal=daily]", "start"),
		k("K-BP-8 weekly", "1707300000", "start", "[renewal=weekly]", "start"),
	},
	"cw-fees.json": {
		k("K-CWFEE-1 399", "0", "feeSkim", "[amount=399]", "want"),
		k("K-CWFEE-1 400", "1", "feeSkim", "[amount=400]", "want"),
		k("K-CWFEE-1 1e8", "250000", "feeSkim", "[amount=100000000]", "want"),
		k("K-CWFEE-2", "10075000", "maxCost", "[id=K-CWFEE-2]", "want"),
		k("K-CWFEE-3", "9974250", "maxCost", "[id=K-CWFEE-3]", "want"),
		k("K-CWFEE-4", "5000000", "maxCost", "[id=K-CWFEE-4]", "want"),
		k("K-CWFEE-4", "24813", "routingFeeReserve", "[id=K-CWFEE-4]", "want"),
		k("K-CWFEE-4", "true", "sendCap", "[id=K-CWFEE-4]", "allowed"),
		k("K-CWFEE-5", "5000001", "maxCost", "[id=K-CWFEE-5]", "want"),
		k("K-CWFEE-5", "false", "sendCap", "[id=K-CWFEE-5]", "allowed"),
		k("K-CWFEE-6 reserve", "10000", "routingFeeReserve", "[amount=100000]", "want"),
		k("K-CWFEE-6 100k", "110250", "maxCost", "[amount=100000]", "want"),
		k("K-CWFEE-6 1M", "1012500", "maxCost", "[amount=1000000]", "want"),
	},
	"npv1.json": {
		k("K-NPV-1", "b577731d8cea3eade64af38643bddd9c17d13718b1421dc7618ea3d74cdb629a", "token", "[id=K-NPV-1]", "hash"),
		k("K-NPV-1", "npv11qqst2amnrkxw504due908pjrhhwec973xuvtzssacascag7hfndk9xsn78h2f", "token", "[id=K-NPV-1]", "token"),
	},
	"nconnection.json": {
		k("K-NCN-1", "nconnection1qqsz9nk30lrm8fhhyckjm0sqksknq22gt92x3cp97sujkzjsy2urr8gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzqajxjumrdaexg6u9jzw", "kat", "string"),
		k("K-NCN-1", "", "decode", "[name=K-NCN-1]", "error"),
	},
	"pow.json": {
		k("K-POW-1", "21", "difficulty", "[id=K-POW-1]", "difficulty"),
		k("K-POW-2", "20", "parseRejection", "[id=K-POW-2]", "difficulty"),
		k("K-POW-3", "[[expiration 1720000060] [nonce <n> 20]]", "tags", "shape"),
		k("K-POW-4 T+86400", "true", "relayRule", "[expiration=1720086400]", "accepted"),
		k("K-POW-4 T+86401", "false", "relayRule", "[expiration=1720086401]", "accepted"),
		k("K-POW-4 T-1", "false", "relayRule", "[expiration=1719999999]", "accepted"),
		k("K-POW-4 none", "false", "relayRule", "[expiration=<nil>,id=K-POW-4]", "accepted"),
	},
	"connection.json": {
		k("K-CH-1", "16c4c4164c27d448128dabf8052dddd5b30c61904b7b7c1b85e1486c37b7a500", "kats", "[id=K-CH-1]", "relayHash"),
		k("K-CH-1", "b5d2b9a2a7f9519d7367521d3a125f882cc34bbcc6f2844aed18533f5f724294", "kats", "[id=K-CH-1]", "labelHash"),
		k("K-CH-1", "c4976825128c4be05a7c553d29852f9611667832eb6d2c096417cd7a6c8817dd", "kats", "[id=K-CH-1]", "digest"),
		k("K-CH-1", "1f7a091bf7eb8691eed90b0c53803747fdb5606c66ee2d6fcf45620297ae38548857d262e8b1e88ffa82f68ef26d335e674f0ee680564300deb48e4842b6b41301", "kats", "[id=K-CH-1]", "signature"),
		k("K-CH-1", kch1, "kats", "[id=K-CH-1]", "string"),
		k("K-CH-1", "368", "kats", "[id=K-CH-1]", "length"),
		k("K-CH-2", "bd39cc19f477bb273774acdef3ed94f8b8a7f9954bb6363a913d6200c48d5c73", "kats", "[id=K-CH-2]", "digest"),
		k("K-CH-2", "1fde47e84298e41bec6555ebe870bd44ec3467ea474386b0a4775b0416a26c55642a57810577e59f31ac0e74164749dbe942ea83f5b8a60cdd62ca16c945ca964c", "kats", "[id=K-CH-2]", "signature"),
		k("K-CH-2", "339", "kats", "[id=K-CH-2]", "length"),
		k("K-CWH-1", "c7c2b59bc693ccb3290c0a51e5c3114e49d382ba14d374ad9b1a17ffdb1750c1", "kats", "[id=K-CWH-1]", "labelHash"),
		k("K-CWH-1", "7c945cb9b96fd8a62c973c42661e572ed186026a012cd7d4882c2eccc1cf1356", "kats", "[id=K-CWH-1]", "digest"),
		k("K-CWH-1", "1f0473ead7683c1db76f61784c503b9fe018d4dbc9db2de5fe604b9ff7017e5ae54ccfaccff692fce2590195e62659f092730798f5a613d6d703903287b05ea05b", "kats", "[id=K-CWH-1]", "signature"),
		k("K-CWH-1", kcwh1, "kats", "[id=K-CWH-1]", "string"),
		k("K-CO-1", "1681e7f0cca2d68c5a2a57e369f815529f0127b2a118adfeafa2f0edadb4d3d5", "kats", "[id=K-CO-1]", "relayHash"),
		k("K-CO-1", "4415045cc4156b398d107e30b03adc967e5cafa1008863146c4467e79f6ed76f", "kats", "[id=K-CO-1]", "labelHash"),
		k("K-CO-1", "0d819a660d269d960d5d898ca15a21fe79eab05c37c2949a973f4377d1180c28", "kats", "[id=K-CO-1]", "digest"),
		k("K-CO-1", "1fe2ee8cdfe9fbe579a7e945c946845b87f16ef8b617d13ce8e1e820c5b1405a8078611658df2f31462bf14858fda192228a782985f0b6eb84fd450704ff443745", "kats", "[id=K-CO-1]", "signature"),
		k("K-CO-1", kco1, "kats", "[id=K-CO-1]", "string"),
		k("K-CO-1", "376", "kats", "[id=K-CO-1]", "length"),
		k("K-CO-2 extra TLV 9", "true", "decode", "[name=K-CO-1 extra TLV 9 is outside the signature]", "want", "verified"),
		k("K-CSIG-1 TLV 9", "", "verify", "[name=K-CH-1 with an extra TLV 9]", "verify"),
		k("K-CHAIN-1 bitcoin-x", "true", "chainName", "[value=bitcoin-x]", "valid"),
		k("K-CHAIN-1 Bitcoin", "false", "chainName", "[value=Bitcoin]", "valid"),
		k("K-CHAIN-1 bit_coin", "false", "chainName", "[value=bit_coin]", "valid"),
		k("K-ONL-1 02", "", "onlineCheck", "[infoIdentity=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798]", "error"),
	},
	"connection-key.json": {
		k("K-CK-1", "22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d", "kats", "[id=K-CK-1]", "key"),
		k("K-CK-1 (neg)", "fec2a66329b3254449b6ab5934972f151fb2f9f1545802fdb06ad8f515b7060f", "kats", "[id=K-CK-1 (neg: the hash never produced)]", "key"),
		k("K-CK-2", "e659b0738cfe438a5d0a58a6eaac063b29537dc9e4570dafac589de080f35c58", "kats", "[id=K-CK-2]", "key"),
		k("K-CK-3", "e16c8f9271f1bc728d668a96e548fedb6da230ac3cb15f5b0a813020695e46e9", "kats", "[id=K-CK-3]", "key"),
		k("K-CK-4", "889e87fc03d0477823a739f269555750a3fd94dacfd1694589bf2bc4eef07b55", "kats", "[id=K-CK-4]", "key"),
		k("K-CK-5", "7beaed89bf6d42d0a7cc67425e8da643156c213496c7695847456dfe8842b518", "kats", "[id=K-CK-5]", "key"),
		k("K-CK-6", "2ca700d6bf1859ef642bb8abe7768f6554e4915b8ca32852e335fc408482183d", "kats", "[id=K-CK-6]", "key"),
		k("K-CK-6", `"a@b"@xn--bcher-kva.example`, "kats", "[id=K-CK-6]", "canonical"),
		k("K-CK-7", "34155e197a74f55bd430d823c3ed9990393530a5122edfda37dfb891014b3bbb", "kats", "[input=XN--BCHER-KVA.EXAMPLE]", "key"),
		k("K-CK-8", "5aaf77cac277108947fa433a956917db62967e209141acb5f605bd6143422e96", "kats", "[id=K-CK-8]", "key"),
		k("K-CK-8 (neg)", "ccf01c68a2769518a7892ffd068d855bf1a798b06058acb87033613b02741501", "kats", "[id=K-CK-8 (neg)]", "key"),
		k("K-CK-9 attested", "2db75fb4d7a8e3005aca09c643b4e6f40142ddcfc18c675509988c1b111d0dcf", "kats", "[id=K-CK-9,platform=github]", "key"),
		k("K-CK-9 dns", "2e93281bfa333b6ab13689eab03c2025404912f99af7b698f19f6ad678eb67e3", "kats", "[input=example.com]", "key"),
		k("K-IDNA-1", "xn--bcher-kva.example", "canonicalUserId", "[id=K-IDNA-1]", "output"),
		k("K-IDNA-2", "xn--bcher-kva.example", "canonicalUserId", "[id=K-IDNA-2]", "output"),
		k("K-IDNA-3", "xn--bcher-kva.example", "canonicalUserId", "[id=K-IDNA-3]", "output"),
		k("K-IDNA-4", "", "canonicalUserId", "[id=K-IDNA-4]", "output"),
		k("K-IDNA-5", "", "canonicalUserId", "[id=K-IDNA-5]", "output"),
		k("K-IDNA-6", "", "canonicalUserId", "[id=K-IDNA-6]", "output"),
	},
	"claim.json": {
		k("K-CLAIM-1", "ad995b77237f369c79c5df82729d465eb9b5b4ddafb815995dee99db8d6b07c8", "kats", "[id=K-CLAIM-1]", "want"),
		k("K-CLAIM-2", "c466018a22842f8b79c7447cebf3a023add78ff7d053d8b715205343ae4ad8df", "kats", "[id=K-CLAIM-2]", "want"),
		k("K-CLAIM-3", "ca9034371c79ec26ec0496b53420a1117d4f765800dfdce138138b139d591f13", "kats", "[id=K-CLAIM-3]", "want"),
		k("K-CLAIM-4", "90aad9efdfc1980322c6248a266df6bca9d766bb360654f5e2bfecccc941bed0", "kats", "[id=K-CLAIM-4]", "want"),
		k("K-CLAIM-4 (neg)", "7d09e57d9def2934d5cbedff5bad3a5c871ea3bf55a674df919e5eb92fc83df4", "kats", "[id=K-CLAIM-4 (neg: refused)]", "want"),
		k("K-CLAIM-5", "d21236b945c9ae88e23fe8fd9bc3559b08b9a6ec6d4a74acd15825314b3d7428", "kats", "[id=K-CLAIM-5]", "want"),
	},
	"nipcw.json": {
		k("K-TERMS-1", "100000:200000:0:monthly", "terms", "[id=K-TERMS-1]", "tag"),
		k("K-TERMS-2", "20000000:50000000:0:never", "terms", "[id=K-TERMS-2]", "tag"),
		k("K-JOIN-1", "f796fb3c192db23c1ea2636c580408c6e574e290c6193e7694d170abedbc65b8", "joinProof", "proofId"),
		k("K-JOIN-1", "1720000300", "joinProof", "deadline"),
	},
}

const (
	ktok1 = "satscash1qqsvvprlj3q76ltdxpz5qm54cp7dshrh3e9cemeu5746czdet3cfaegpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgprpmhxue69uhkyctrdd6hqtn90psk6urvv5hxuet5qgsqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8crqyqs2sfq7gvnhvt0jjxg049a9kg9jnl306hyqexhxn6gw3e0928ftmtxr7n5r2emz4x3r8q6lrx6hgjhzrykwj9wtnchnh78hjcz23pr6n2tf7sxpqqqqqqqqqq9yzq8qnkhn68lpqqszp39gk7"
	kch1  = "cashhub1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyqszzg3rysjjvfeg9y4zktpd9chnqvfjxv6r2d3h8qun5weu85lr7qcsg9kxjcm9yaejqsmpwd5zqjr4vgzzq7d7vel0nh9m4326qc54e6rskpczn07dktww9rv4nu5ptvt0s9ucq4q377sfr0m7hp53amvskrznsqm50ld4vpkxdm3ddl852cszj7hrs4yg2lfx9693az8l4qhk3mex6v67va8sae5q2epsph453eyy9d45zvqsvpmzd96xxmmfdcvlu0w2"
	kcwh1 = "circlehub1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyqszzg3rysjjvfeg9y4zktpd9chnqvfjxv6r2d3h8qun5weu85lr7qcng9jxzfmnyprxzmtfd3ujqsmfwf3kcegyypumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtesp2pruz886khdq7pmdm0v9uyc5pmnlsp34xme8djme07vp9elacp0edw2nx04n8ldyhuufvsr90xyevlpynnq7v0tfsn6mts8ypjs7c9agzmqcrky6t5vdhkjms0uy6sx"
	kco1  = "cashorder1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzypqyzsjrg3z5v36gf99yknzdfe84q52j2d2924jhtpv45k6ut4097qc5g9kxjcm9yaejqcmpwd5zqcm0w4h8getjqss8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xq9gy079m5vml5lhete5l55tj2xs3dc0utwlzmp05fuars7sgx9k9q94qrcvyt93he0x9rzhu2gtr76ry3z3fuznp0skm4cfl29quz073phg5rqwcnfw33k76twqxha8f"
)

func init() {
	katChecks["hub-group.json"] = []kat{
		k("K-HG-1", "3bbf9943", "hubGroupFor", "[hub=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798]", "group"),
		k("K-HG-1 raw bytes", "132f39a9", "hubGroupFor", "[hub=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798]", "notRawBytes"),
		k("K-HG-1 spec Hub", "ed79e8ff", "hubGroupFor", "[hub=f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9]", "group"),
	}
	katChecks["reply-key.json"] = []kat{
		k("K-RK-1", "aede656a94d03cfa382dcc742ec44cec9248ed2be2b71bf0fa92ed48298705da", "derive", "[id=K-RK-1]", "replyKey"),
		k("K-RK-2", "a0953747794eb0fc06b187bf8a1449f60716b788b850b7adfe82e11753d03a7b", "derive", "[id=K-RK-2]", "replyKey"),
		k("K-RK-3", "d80410259b62e3676c3a95a9b1ccdd639c8a8c6cbc48ec1d7bc375774f2e16b1", "derive", "[id=K-RK-3]", "replyKey"),
		k("K-RK-4", "76fd816d6581bd072b175ea7008fb18b4a32230d17c649a01e645b16a73131f7", "negative", "[id=K-RK-4]", "replyKey"),
		k("K-RK-5 extract", "3f0cb243ab7de6ca7d11f2cc05183644fbdbef2af2efc7cd1ea429906b71569b", "negative", "[id=K-RK-5,note=an Extract step first (zero salt)]", "replyKey"),
		k("K-RK-5 v2", "11193f237e47b54c2a9fc9466a524b2d6d94e36b980b37fb8d94c0ed8557841b", "negative", "[id=K-RK-5,note=label nipcash-reply-v2]", "replyKey"),
	}
	katChecks["padding.json"] = []kat{
		k("K-PAD-1", "8192", "paddedSize", "[id=K-PAD-1,n=5000]", "padded"),
		k("K-PAD-1 max_bytes", "6000", "paddedSize", "[id=K-PAD-1,padded=6000]", "padded"),
	}
	katChecks["proof.json"] = []kat{
		k("K-PROOF-1", "a121c54b100a68efbda151d0fe01c4290b7a9ea41c22409e916a0e9cb7aabb0b", "kats", "[id=K-PROOF-1]", "eventId"),
		k("K-PROOF-2", "7e4908cda700cd019f244c5c4dafc43c321a23cbc023daec37c6011bfa802c53", "kats", "[id=K-PROOF-2]", "eventId"),
		k("K-PH-1", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "ph", "[id=K-PH-1]", "hash"),
		k("K-PH-1 absent", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "ph", "[id=K-PH-1,params=]", "hash"),
		k("K-PH-2", "ad912f7b3df717e48cbec6d735d0a02bdef1569dd700e374445aea82120592d5", "ph", "[id=K-PH-2]", "hash"),
		k("K-PH-3", "88fe51f35b9c0a5ee45347afdaa517b2cb3ebc5916e4e0fe3b2fe42494e616a4", "ph", "[id=K-PH-3]", "hash"),
		k("K-PH-4 escaped", "2625065109f911142b060568bcfeda2e1f83514be6607bcc039feedbdb3e7b60", "ph", "[id=K-PH-4,note=< escaped as \\u003c]", "hash"),
		k("K-PH-4 float", "b5900d536afbcdce0fe359557e6b7b5c0258d41ddbad09ca7a2cda99ae5b89c6", "ph", "[id=K-PH-4,note=the number rounded through a float]", "hash"),
	}
	env := []kat{}
	for _, c := range []struct{ name, want string }{
		{"pubkey redeem", "3"}, {"bearer redeem", "1"}, {"CK transfer", "4"}, {"consolidate 3 pubkey sources", "5"},
		{"consolidate 2 pubkey + 1 CK", "6"}, {"signed status", "2"}, {"cash-mode status", "1"}, {"private join", "3"},
	} {
		env = append(env, k("K-VB-1 "+c.name, c.want, "verificationCost", "[id=K-VB-1,name="+c.name+"]", "cost"))
	}
	for _, c := range []struct{ name, want string }{
		{"pubkey quote", "2"}, {"CK quote", "3"}, {"cash-mode quote", "1"}, {"pubkey withdraw", "4"},
		{"CK withdraw", "5"}, {"bearer withdraw", "2"}, {"cancel by pubkey", "2"}, {"bearer cancel", "1"},
	} {
		env = append(env, k("K-VB-2 "+c.name, c.want, "verificationCost", "[id=K-VB-2,name="+c.name+"]", "cost"))
	}
	env = append(env, k("cancel served as cash_lookup", "cash_lookup", "serving", "[name=cash_withdraw cancel: served as cash_lookup]", "serving"))
	katChecks["envelope.json"] = env
	katChecks["nip47.json"] = []kat{
		k("K-N47-1", "[[p 62c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7] [encryption nip44_v2] [expiration 1720000060]]", "requests", "[id=K-N47-1]", "event", "tags"),
		k("K-N47-1 id", "d412c7541263817655e7595ae00ef3c666eaa666573f22d308d9e4aee8c6a609", "requests", "[id=K-N47-1]", "event", "id"),
	}
	noKATs["announcement.json"] = true
}

func init() {
	w := []kat{
		k("K-WQ-1", "bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22", "quotes", "[id=K-WQ-1]", "event", "id"),
		k("K-WQ-1 fee", "1742000", "quotes", "[id=K-WQ-1]", "feeMillis"),
		k("K-WQ-2", "484362992237afca0ec22c8ab27a6abb6214ac0294e38f702a5bb75e4678d276", "quotes", "[id=K-WQ-2]", "event", "id"),
		k("K-WQ-3", "a913107c809253d590766e54f89cd2d323b460303f00650e7df9660d539227be", "quotes", "[id=K-WQ-3]", "event", "id"),
		k("K-WQ-3 verifies", "", "quotes", "[id=K-WQ-3]", "verify"),
		k("K-WR-1", "5947d7c33d783f94b3b4c1a96ebc8991ed28f1b069b71e03376cba8caa98a720", "requestHash", "[id=K-WR-1]", "hash"),
		k("K-WR-2", "2b376b910505799c6f92edcb3c3543e47e73fc210b877cdd91738c367d21cfef", "receipts", "[id=K-WR-2]", "event", "id"),
		k("K-WR-3 hash", "0f5019117b865df3d86a6856ba8cf5383850ae9d833ecf7cc9a609552cb6c413", "requestHash", "[id=K-WR-3]", "hash"),
		k("K-WR-3 id", "7060d4c8e4f8ab862a5105a4d0573465a70f62f9ec8e11e6c8d22595f73f4c90", "receipts", "[id=K-WR-3]", "event", "id"),
		k("K-WR-4", "a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811", "requestHash", "[id=K-WR-4]", "hash"),
		k("K-WR-4 refused", "nipcash: the withdrawal receipt is invalid: request_hash", "verifyReceipt", "[id=K-WR-4]", "error"),
		k("K-CLAIM-5", "d21236b945c9ae88e23fe8fd9bc3559b08b9a6ec6d4a74acd15825314b3d7428", "claimProof", "want"),
		k("K-WFEE-6", "nipcash: a ppm rate is at most 1000000: withdraw_fee_ppm 1000001", "withdrawFee", "[id=K-WFEE-6]", "error"),
		k("K-ADDR-6", "network", "address", "[id=K-ADDR-6]", "class"),
		k("K-ADDR-12", "script_type", "address", "[id=K-ADDR-12]", "class"),
		k("K-ADDR-10 normalize", kAddr1lit, "normalizeAddress", "[id=K-ADDR-10]", "output"),
		k("K-ADDR-13 tb", "tb", "classifyAddressAmong", "[address=tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx]", "hrp"),
		k("K-ADDR-13 bcrt", "bcrt", "classifyAddressAmong", "[address=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080]", "hrp"),
		k("K-ADDR-13 zz", "network", "classifyAddressAmong", "[address=zz1qw508d6qejxtdg4y5r3zarvary0c5xw7k3c49eg]", "class"),
		k("K-WDET-1", "own_address", "detail", "[id=K-WDET-1]", "detail"),
		k("K-WDET-2", "", "detail", "[id=K-WDET-2]", "detail"),
		k("K-WDET-3", "", "detail", "[id=K-WDET-3]", "detail"),
		k("K-WHOLD-1 870413", "true", "quoteValidAt", "[tip=870413]", "valid"),
		k("K-WHOLD-1 870414", "false", "quoteValidAt", "[tip=870414]", "valid"),
		k("K-WCAN-1", "not_due", "cancel", "[id=K-WCAN-1]", "step"),
		k("K-WCAN-2", "cancel_now", "cancel", "[id=K-WCAN-2]", "step"),
		k("K-WCAN-3", "invalidate_then_cancel", "cancel", "[id=K-WCAN-3]", "step"),
		k("K-WCAN-4", "RESTRICTED", "cancel", "[id=K-WCAN-4]", "code"),
		k("K-WCAN-5", "true", "cancel", "[id=K-WCAN-5]", "invalidate"),
		k("K-WCAN-6", "false", "cancel", "[id=K-WCAN-6]", "invalidate"),
		k("K-WREM-1", "1722682000", "remintExpiry", "[id=K-WREM-1]", "expiresAt"),
		k("K-WREM-2", "<nil>", "remintExpiry", "[id=K-WREM-2]", "expiresAt"),
		k("K-WREM-3", "1730000000", "remintExpiry", "[id=K-WREM-3]", "expiresAt"),
		k("K-WREM-4", "<nil>", "remintExpiry", "[id=K-WREM-4]", "expiresAt"),
		k("K-WRET-1", "true", "retention", "[id=K-WRET-1,now=1099511627776]", "retained"),
		k("K-WRET-2 at", "true", "retention", "[id=K-WRET-2,now=1722692000]", "retained"),
		k("K-WRET-2 after", "false", "retention", "[id=K-WRET-2,now=1722692001]", "retained"),
		k("K-WRET-3", "true", "retention", "[id=K-WRET-3]", "retained"),
	}
	for i, r := range []struct{ id, addr, st string }{
		{"K-ADDR-1", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "[0 20]"},
		{"K-ADDR-2", "", "[0 32]"}, {"K-ADDR-3", "", "[1 32]"}, {"K-ADDR-4", "", "[2 16]"}, {"K-ADDR-5", "", "[1 20]"},
	} {
		_ = i
		w = append(w, k(r.id, r.st, "address", "[id="+r.id+"]", "scriptType"))
	}
	for _, id := range []string{"K-ADDR-7", "K-ADDR-8", "K-ADDR-9", "K-ADDR-10", "K-ADDR-11"} {
		w = append(w, k(id, "malformed", "address", "[id="+id+"]", "class"))
	}
	for _, c := range []struct{ id, hub, fee, payout string }{
		{"K-WFEE-1", "542000", "1742000", "19258000"}, {"K-WFEE-2", "542000", "1743000", "19257000"}, {"K-WFEE-3", "0", "205000", "20795000"},
		{"K-WFEE-4", "502000", "1000000", "0"}, {"K-WFEE-5", "542001", "1742500", "19258000"},
	} {
		w = append(w, k(c.id+" hub", c.hub, "withdrawFee", "[id="+c.id+"]", "hubFeeMillis"),
			k(c.id+" fee", c.fee, "withdrawFee", "[id="+c.id+"]", "feeMillis"),
			k(c.id+" payout", c.payout, "withdrawFee", "[id="+c.id+"]", "payoutMillis"))
	}
	for _, c := range []struct{ name, want string }{
		{"pubkey quote", "2"}, {"CK quote", "3"}, {"cash-mode quote", "1"}, {"pubkey withdraw", "4"},
		{"CK withdraw", "5"}, {"bearer withdraw", "2"}, {"cancel by pubkey", "2"}, {"bearer cancel", "1"},
	} {
		w = append(w, k("K-VB-2 "+c.name, c.want, "verificationCost", "[name="+c.name+"]", "cost"))
	}
	katChecks["withdraw.json"] = w

	katChecks["order.json"] = []kat{
		k("K-BK-1 sk", "c853759de7b777f3588569e48461ec8ad52dbea4c8829b759a05e352cf649dea", "buyerKey", "[id=K-BK-1]", "buyerSk"),
		k("K-BK-1 pk", "a5a70781e66224a1a4e26614b36328c1a8913f1a2c80bca00fbb2e5af993c8a3", "buyerKey", "[id=K-BK-1]", "buyerPk"),
		k("K-BK-1 commitment", "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd", "buyerKey", "[id=K-BK-1]", "commitment"),
		k("K-OFEE-1 fee", "22000", "orderFee", "[id=K-OFEE-1]", "feeMillis"),
		k("K-OFEE-1 pay", "21022000", "orderFee", "[id=K-OFEE-1]", "payMillis"),
		k("K-OFEE-2 fee", "63000", "orderFee", "[id=K-OFEE-2]", "feeMillis"),
		k("K-OFEE-2 pay", "21063000", "orderFee", "[id=K-OFEE-2]", "payMillis"),
		k("K-OFEE-3 fee", "64000", "orderFee", "[id=K-OFEE-3]", "feeMillis"),
		k("K-OFEE-3 pay", "21064000", "orderFee", "[id=K-OFEE-3]", "payMillis"),
		k("K-OFEE-2 confirmations", "1", "confirmations", "[id=K-TIER-1]", "n"),
		k("K-TIER-1", "1", "confirmations", "[id=K-TIER-1]", "n"),
		k("K-TIER-2", "3", "confirmations", "[id=K-TIER-2]", "n"),
		k("K-TIER-3", "6", "confirmations", "[id=K-TIER-3]", "n"),
		k("K-SPLIT-1", "[1000000000 1000000000 500000000]", "mintSplit", "[id=K-SPLIT-1]", "bills"),
		k("K-OMINT-1", "[21000000]", "mintSplit", "[id=K-OMINT-1]", "bills"),
		k("K-OMINT-2", "[19937000]", "mintSplit", "[id=K-OMINT-2]", "bills"),
		k("K-OMINT-3", "[24937000]", "mintSplit", "[id=K-OMINT-3]", "bills"),
		k("K-OMINT-4", "[9937000]", "mintSplit", "[id=K-OMINT-4]", "bills"),
		k("K-OMINT-5", "[]", "mintSplit", "[id=K-OMINT-5]", "bills"),
		k("K-ON-1 filter", "map[#p:[0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef] kinds:[23189]]", "notice", "filter"),
		k("K-ON-1 tags", "[[p 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef]]", "notice", "noticeTags"),
		k("K-ON-1 content", "", "notice", "noticeContent"),
		k("retired connection", "true", "getInfo", "[name=a retired connection: cash_order {}]", "sellsNothing"),
	}
	katChecks["pocket.json"] = []kat{
		k("K-POCKET-6 pending", "c49dbd482343b3c68e9ba59ae6d120b991f17bd88b98620145eac562ad6b2c39", "withdraw", "[name=the pending entry: pubkey slice]", "rumor", "id"),
		k("K-POCKET-6 cash mode", "1add82fd822acf561e8934d09f063894eb5dbb38979794c392135676899ba246", "withdraw", "[name=the pending entry: cash-mode slice (remint secret)]", "rumor", "id"),
		k("K-POCKET-6 receipt", "37e38de3fba644966e59095d2da2b7d51277137ee6ee43024ea0b227dcf7a661", "applyWithdraw", "[name=first receipt (queued)]", "writes", "[id=K-POCKET-6]", "rumor", "id"),
		k("K-POCKET-6 rewrite", "3137f0f66c68af647fe3f2f2942042c8346ce4e6c63ad952c5aea820373fa0e4", "withdraw", "[name=the done entry rewritten]", "rumor", "id"),
		k("K-POCKET-4", "map[bitcoin:42000 flokicoin:7000]", "balance", "balance"),
		k("K-POCKET-3 winner", "0000000000000000000000000000000000000000000000000000000000000000", "resolve", "[id=K-POCKET-3]", "winnerRumorId"),
		k("K-POCKET-1", "e284c7c39231796c650f29c2ac6b092e778a6386b558db678c678fedd6ff9489", "rumors", "[id=K-POCKET-1]", "rumor", "id"),
		k("K-POCKET-2", "b606d719b13bf64c36333ac4c0855dd2768e9b657cda69b7604a1aac5dca85eb", "rumors", "[id=K-POCKET-2]", "rumor", "id"),
		k("K-POCKET-5", "a6f66587e3af2ee863db7d34b5bef056648aef576ae03cb50abafa6aa168c7d0", "rumors", "[id=K-POCKET-5]", "rumor", "id"),
		k("K-POCKET-5 close (Lightning minted)", "true", "order", "[name=Lightning minted: the bill then done]", "done"),
		k("K-POCKET-5 open (on-chain minted)", "false", "order", "[name=on-chain minted stays open]", "done"),
	}
	katChecks["zap.json"] = []kat{
		k("K-CZ-1", "0", "parse", "[id=K-CZ-1]", "rule"),
		k("K-CZ-2", "2", "parse", "[id=K-CZ-2]", "rule"),
		k("K-CZ-3", "2", "parse", "[id=K-CZ-3]", "rule"),
		k("K-CZ-4", "2", "parse", "[id=K-CZ-4]", "rule"),
		k("K-CZ-5", "2", "parse", "[id=K-CZ-5]", "rule"),
		k("K-CZ-6", "2", "parse", "[id=K-CZ-6]", "rule"),
	}
	katChecks["altzap.json"] = []kat{
		k("K-AZ-1", "e0f32bed48057944056e7fb1d74c00569ecb2349882d0e2985f2ae480b71f4c5", "kat", "event", "id"),
		k("K-AZ-1 ck", "ffed85070e86f6ac651aa82b91310ca01895a7432bb0f8224fe74d7b21ab18c1", "kat", "connectionKey"),
	}
	katChecks["listing.json"] = []kat{
		k("K-LIST-1", "a2aeaaa40b57de5807c1a466060e58111c23eaa96390a0b894982bcafbe555b0", "events", "[id=K-LIST-1]", "event", "id"),
		k("K-LIST-1 address", "31190:79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798:f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "parseListing", "[name=K-LIST-1]", "want", "address"),
		k("K-LIST-2", "25d3a99b0b593aa70ad5d848a91cd300062f6c4a479bc7005d66277897a96506", "events", "[id=K-LIST-2]", "event", "id"),
		k("K-LDEL-1", "5aa2a615eb258246769d21389dee11481066e3ef3809e9a25a7847acd848d37b", "events", "[id=K-LDEL-1]", "event", "id"),
		k("K-OPS-1", "3b74fc1d53fa35a72ba235ce398dc29e599f19e202fc5c16bec156179e1480a0", "events", "[id=K-OPS-1]", "event", "id"),
		k("K-REC-1", "1ffb32f70209a551300255197aad28472ef74130e432011039d6b5da5d45a5f8", "events", "[id=K-REC-1]", "event", "id"),
		k("K-REP-1", "00cc61c6f4914fac8dfc65a4a29057f687f4af1be394213658e7d53d5e1c1abd", "events", "[id=K-REP-1]", "event", "id"),
		k("K-REP-1 reason", "no_payout", "reports", "[name=K-REP-1]", "want", "reason"),
		k("K-LEXP-1", "1795305600", "expiresAt", "[id=K-LEXP-1]", "expiresAt"),
		k("K-LEXP-2", "1795305600", "expiresAt", "[id=K-LEXP-2]", "expiresAt"),
		k("K-LEXP-3", "1793000000", "expiresAt", "[id=K-LEXP-3]", "expiresAt"),
		k("K-LEXP 900 s", "[true]", "versions", "[name=seen 900 s ahead: accepted]", "accepted"),
		k("K-LEXP 901 s", "[false]", "versions", "[name=seen 901 s ahead: ignored]", "accepted"),
		k("K-LVER-1 refused", "[true false]", "versions", "[name=K-LIST-1 offered after K-LIST-2: refused]", "accepted"),
		k("K-LVER-1 remembered", "[true false]", "versions", "[name=K-LIST-2 expired then K-LIST-1 again: still refused]", "accepted"),
		k("K-OPS-1 verified", "true", "operatorVerified", "[name=K-OPS-1 with K-LIST-1: verified]", "verified"),
		k("K-TXT-1 1", "Alice's cash counter", "sanitizeText", "[in=Alice\u200b's\u202e cash counter]", "out"),
		k("K-TXT-1 2", " Alice", "sanitizeText", "[in=✔ Alice]", "out"),
		k("K-TXT-1 3", "A B", "sanitizeText", "[in=A\nB]", "out"),
	}
	l := []kat{}
	for _, c := range []struct{ id, ev, step string }{
		{"K-LSP-1", "d87841c795e01ba75208a603bc0bdfe7f2015ab3876860501e2f09d0c257a45b", "0"},
		{"K-LSP-2", "4888cfb893cec3cd2ab49f26504f9914e841933a8e3f3e5725eb27313b951158", "0"},
		{"K-LSP-3", "9e63298039c075dc61ff438ff8b642ed7463d15f6d9e10b14f738f9cddf1c0ba", "2"},
		{"K-LSP-4", "b9d668ad9b8dc89a01df7fe8f8c429204e946110c9a8768bafbf76c9503d4b8c", "3"},
		{"K-LSP-5", "c49b0d6188e1829ffd507ee217589a05cd4eeaed22014bcf3a57d41c58b9adff", "4"},
		{"K-LSP-6", "b9601b6f837a62e054285d0b2c62ece02d3db65be8f1d27c2ea107806ed3b974", "5"},
	} {
		l = append(l, k(c.id, c.ev, "events", "[id="+c.id+"]", "event", "id"), k(c.id+" step", c.step, "events", "[id="+c.id+"]", "step"))
	}
	katChecks["lsp-announcement.json"] = l
}

const kAddr1lit = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
