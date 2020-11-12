double ? = Double;
string ? = String;

int32 = Int32;
int53 = Int53;
int64 = Int64;
bytes = Bytes;
secureString = SecureString;
secureBytes = SecureBytes;

object ? = Object;
function ? = Function;

boolFalse = Bool;
boolTrue = Bool;

vector {t:Type} # [ t ] = Vector t;

error code:int32 message:string = Error;
ok = Ok;

keyStoreTypeDirectory directory:string = KeyStoreType;
keyStoreTypeInMemory = KeyStoreType;

config config:string blockchain_name:string use_callbacks_for_network:Bool ignore_cache:Bool = Config;

options config:config keystore_type:KeyStoreType = Options;
options.configInfo default_wallet_id:int64 default_rwallet_init_public_key:string = options.ConfigInfo;
options.info config_info:options.configInfo = options.Info;

key public_key:string secret:secureBytes = Key;
inputKeyRegular key:key local_password:secureBytes = InputKey;
inputKeyFake = InputKey;
exportedKey word_list:vector<secureString> = ExportedKey;
exportedPemKey pem:secureString = ExportedPemKey;
exportedEncryptedKey data:secureBytes = ExportedEncryptedKey;
exportedUnencryptedKey data:secureBytes = ExportedUnencryptedKey;

bip39Hints words:vector<string> = Bip39Hints;

adnlAddress adnl_address:string = AdnlAddress;

accountAddress account_address:string = AccountAddress;

unpackedAccountAddress workchain_id:int32 bounceable:Bool testnet:Bool addr:bytes = UnpackedAccountAddress;

internal.transactionId lt:int64 hash:bytes = internal.TransactionId;

ton.blockId workchain:int32 shard:int64 seqno:int32 = ton.BlockId;
ton.blockIds ids:vector<ton.blockId> = ton.BlockIds;
//@param root_hash  int256
//@param file_hash  int256
ton.blockIdExt workchain:int32 shard:int64 seqno:int32 root_hash:bytes file_hash:bytes = ton.BlockIdExt;
//@param root_hash  int256
//@param file_hash  int256
ton.zeroStateIdExt workchain:int32 root_hash:bytes file_hash:bytes = ton.ZeroStateIdExt;

raw.fullAccountState balance:int64 code:bytes data:bytes last_transaction_id:internal.transactionId block_id:ton.blockIdExt frozen_hash:bytes sync_utime:int53 = raw.FullAccountState;
raw.message source:accountAddress destination:accountAddress value:int64 fwd_fee:int64 ihr_fee:int64 created_lt:int64 bounce:Bool bounced:Bool body_hash:bytes msg_data:msg.Data = raw.Message;
raw.transaction utime:int53 data:bytes transaction_id:internal.transactionId aborted:Bool destroyed:Bool fee:int64 storage_fee:int64 other_fee:int64 in_msg:raw.message out_msgs:vector<raw.message> = raw.Transaction;
raw.transactions transactions:vector<raw.transaction> previous_transaction_id:internal.transactionId = raw.Transactions;

pchan.config alice_public_key:string alice_address:accountAddress bob_public_key:string bob_address:accountAddress init_timeout:int32 close_timeout:int32 channel_id:int64 = pchan.Config;

raw.initialAccountState code:bytes data:bytes = InitialAccountState;
wallet.v3.initialAccountState public_key:string wallet_id:int64 = InitialAccountState;
wallet.highload.v1.initialAccountState public_key:string wallet_id:int64 = InitialAccountState;
wallet.highload.v2.initialAccountState public_key:string wallet_id:int64 = InitialAccountState;

rwallet.limit seconds:int32 value:int64 = rwallet.Limit;
rwallet.config start_at:int53 limits:vector<rwallet.limit> = rwallet.Config;
rwallet.initialAccountState init_public_key:string public_key:string wallet_id:int64 = InitialAccountState;

dns.initialAccountState public_key:string wallet_id:int64 = InitialAccountState;
pchan.initialAccountState config:pchan.config = InitialAccountState;

raw.accountState code:bytes data:bytes frozen_hash:bytes = AccountState;
wallet.v3.accountState wallet_id:int64 seqno:int32 = AccountState;
wallet.highload.v1.accountState wallet_id:int64 seqno:int32 = AccountState;
wallet.highload.v2.accountState wallet_id:int64 = AccountState;
dns.accountState wallet_id:int64 = AccountState;
rwallet.accountState wallet_id:int64 seqno:int32 unlocked_balance:int64 config:rwallet.config = AccountState;

pchan.stateInit signed_A:Bool signed_B:Bool min_A:int64 min_B:int64 expire_at:int53 A:int64 B:int64 = pchan.State;
pchan.stateClose signed_A:Bool signed_B:Bool min_A:int64 min_B:int64 expire_at:int53 A:int64 B:int64 = pchan.State;
pchan.statePayout A:int64 B:int64 = pchan.State;

pchan.accountState config:pchan.config state:pchan.State description:string = AccountState;
uninited.accountState frozen_hash:bytes = AccountState;

fullAccountState address:accountAddress balance:int64 last_transaction_id:internal.transactionId block_id:ton.blockIdExt sync_utime:int53 account_state:AccountState revision:int32 = FullAccountState;

accountRevisionList revisions:vector<fullAccountState> = AccountRevisionList;
accountList accounts:vector<fullAccountState> = AccountList;

syncStateDone = SyncState;
syncStateInProgress from_seqno:int32 to_seqno:int32 current_seqno:int32 = SyncState;

transactionSearchResult sync_utime:int32 found:Bool lt:int64 hash:bytes = TransactionSearchResult;

//
// MSG
//

msg.dataRaw body:bytes init_state:bytes = msg.Data;
msg.dataText text:bytes = msg.Data;
msg.dataDecryptedText text:bytes = msg.Data;
msg.dataEncryptedText text:bytes = msg.Data;

msg.dataEncrypted source:accountAddress data:msg.Data = msg.DataEncrypted;
msg.dataDecrypted proof:bytes data:msg.Data = msg.DataDecrypted;

msg.dataEncryptedArray elements:vector<msg.dataEncrypted> = msg.DataEncryptedArray;
msg.dataDecryptedArray elements:vector<msg.dataDecrypted> = msg.DataDecryptedArray;

msg.message destination:accountAddress public_key:string amount:int64 data:msg.Data = msg.Message;

//
// FreeTON abi
//

ftabi.paramUint size:int32 = ftabi.Param;
ftabi.paramInt size:int32 = ftabi.Param;
ftabi.paramBool = ftabi.Param;
ftabi.paramTuple itemTypes:vector<ftabi.Param> = ftabi.Param;
ftabi.paramArray itemType:ftabi.Param = ftabi.Param;
ftabi.paramFixedArray itemType:ftabi.Param size:int32 = ftabi.Param;
ftabi.paramCell = ftabi.Param;
//ftabi.paramMap keyType:ftabi.Param valueType:ftabi.Param = ftabi.Param;
ftabi.paramAddress = ftabi.Param;
ftabi.paramBytes = ftabi.Param;
ftabi.paramFixedBytes size:int32 = ftabi.Param;
ftabi.paramGram = ftabi.Param;
ftabi.paramTime = ftabi.Param;
ftabi.paramExpire = ftabi.Param;
ftabi.paramPublicKey = ftabi.Param;

ftabi.valueInt param:ftabi.Param value:int64 = ftabi.Value;
ftabi.valueBigInt param:ftabi.Param value:bytes = ftabi.Value;
ftabi.valueBool param:ftabi.Param value:Bool = ftabi.Value;
ftabi.valueTuple param:ftabi.Param values:vector<ftabi.Value> = ftabi.Value;
ftabi.valueCell param:ftabi.Param value:tvm.Cell = ftabi.Value;
ftabi.valueAddress param:ftabi.Param value:AccountAddress = ftabi.Value;
ftabi.valueBytes param:ftabi.Param value:bytes = ftabi.Value;
ftabi.valueGram param:ftabi.Param value:int64 = ftabi.Value;
ftabi.valueTime param:ftabi.Param value:int64 = ftabi.Value;
ftabi.valueExpire param:ftabi.Param value:int32 = ftabi.Value;
ftabi.valuePublicKey param:ftabi.Param value:SecureString = ftabi.Value;

ftabi.namedParam name:string param:ftabi.Param = ftabi.NamedParam;
ftabi.namedValue name:string value:ftabi.Value = ftabi.NamedValue;

ftabi.functionId id:int32 = ftabi.FunctionId;
ftabi.functionSignature data:string = ftabi.FunctionSignature;
ftabi.messageBody data:bytes = ftabi.MessageBody;

ftabi.function name:string header_params:vector<ftabi.NamedParam> input_params:vector<ftabi.Param> output_params:vector<ftabi.Param> input_id:int32 output_id:int32 = ftabi.Function;

ftabi.functionCallJson value:string = ftabi.FunctionCall;
ftabi.functionCallExternal header_values:vector<ftabi.NamedValue> input_values:vector<ftabi.Value> = ftabi.FunctionCall;
ftabi.functionCallExternalSigned header_values:vector<ftabi.NamedValue> input_values:vector<ftabi.Value> key:secureBytes = ftabi.FunctionCall;
ftabi.functionCallInternal header_values:vector<ftabi.NamedValue> input_values:vector<ftabi.Value> = ftabi.FunctionCall;
ftabi.functionCallInternalSigned header_values:vector<ftabi.NamedValue> input_values:vector<ftabi.Value> key:secureBytes = ftabi.FunctionCall;

ftabi.decodedInput header_values:vector<ftabi.Value> values:vector<ftabi.Value> = ftabi.DecodedInput;
ftabi.decodedOutput values:vector<ftabi.Value> = ftabi.DecodedOutput;

ftabi.jsonDecodedInput value:string = ftabi.JsonDecodedInput;
ftabi.jsonDecodedOutput value:string = ftabi.JsonDecodedOutput;

//@param hash   int256
ftabi.stateInit data:bytes hash:bytes = ftabi.StateInit;

//
// DNS
//

dns.entryDataUnknown bytes:bytes = dns.EntryData;
dns.entryDataText text:string = dns.EntryData;
dns.entryDataNextResolver resolver:AccountAddress = dns.EntryData;
dns.entryDataSmcAddress smc_address:AccountAddress = dns.EntryData;
dns.entryDataAdnlAddress adnl_address:AdnlAddress = dns.EntryData;

dns.entry name:string category:int32 entry:dns.EntryData = dns.Entry;

dns.actionDeleteAll = dns.Action;
// use category = 0 to delete all entries
dns.actionDelete name:string category:int32 = dns.Action;
dns.actionSet entry:dns.entry = dns.Action;

dns.resolved entries:vector<dns.entry> = dns.Resolved;


//
// Payment channel
//
pchan.promise signature:bytes promise_A:int64 promise_B:int64 channel_id:int64 = pchan.Promise;

pchan.actionInit inc_A:int64 inc_B:int64 min_A:int64 min_B:int64 = pchan.Action;
pchan.actionClose extra_A:int64 extra_B:int64 promise:pchan.promise = pchan.Action;
pchan.actionTimeout = pchan.Action;

//
// Restricted wallet initialization
//
rwallet.actionInit config:rwallet.config = rwallet.Action;

//
// Actions
//

actionNoop  = Action;
actionMsg messages:vector<msg.message> allow_send_to_uninited:Bool = Action;
actionDns actions:vector<dns.Action> = Action;
actionPchan action:pchan.Action = Action;
actionRwallet action:rwallet.actionInit = Action;
//actionMultisig actions:vector<multisig.order> = Action;

fees in_fwd_fee:int53 storage_fee:int53 gas_fee:int53 fwd_fee:int53 = Fees;
query.fees source_fees:fees destination_fees:vector<fees> = query.Fees;
// query.emulationResult exit_code:int32 fees:fees = query.EmulationResult;
query.info id:int53 valid_until:int53 body_hash:bytes body:bytes init_state:bytes = query.Info;

tvm.slice bytes:bytes = tvm.Slice;
tvm.cell bytes:bytes = tvm.Cell;
tvm.numberDecimal number:string = tvm.Number;
tvm.tuple elements:vector<tvm.StackEntry> = tvm.Tuple;
tvm.list elements:vector<tvm.StackEntry> = tvm.List;

tvm.stackEntrySlice slice:tvm.slice = tvm.StackEntry;
tvm.stackEntryCell cell:tvm.cell = tvm.StackEntry;
tvm.stackEntryNumber number:tvm.Number = tvm.StackEntry;
tvm.stackEntryTuple tuple:tvm.Tuple = tvm.StackEntry;
tvm.stackEntryList list:tvm.List = tvm.StackEntry;
tvm.stackEntryUnsupported = tvm.StackEntry;

smc.info id:int53 = smc.Info;

smc.methodIdNumber number:int32 = smc.MethodId;
smc.methodIdName name:string = smc.MethodId;

smc.runResult gas_used:int53 stack:vector<tvm.StackEntry> exit_code:int32 = smc.RunResult;

updateSendLiteServerQuery id:int64 data:bytes = Update;
updateSyncState sync_state:SyncState = Update;

//@class LogStream @description Describes a stream to which tonlib internal log is written

//@description The log is written to stderr or an OS specific log
logStreamDefault = LogStream;

//@description The log is written to a file @path Path to the file to where the internal tonlib log will be written @max_file_size Maximum size of the file to where the internal tonlib log is written before the file will be auto-rotated
logStreamFile path:string max_file_size:int53 = LogStream;

//@description The log is written nowhere
logStreamEmpty = LogStream;


//@description Contains a tonlib internal log verbosity level @verbosity_level Log verbosity level
logVerbosityLevel verbosity_level:int32 = LogVerbosityLevel;

//@description Contains a list of available tonlib internal log tags @tags List of log tags
logTags tags:vector<string> = LogTags;

data bytes:secureBytes = Data;

//
// LiteServer
//

//@param id         int256
liteServer.accountId workchain:int32 id:bytes = liteServer.AccountId;
liteServer.info now:int53 version:int32 capabilities:int64 = liteServer.Info;
liteServer.currentTime now:int32 = liteServer.CurrentTime;
//@param state_root_hash    int256
liteServer.masterchainInfo last:ton.BlockIdExt state_root_hash:bytes init:ton.zeroStateIdExt = liteServer.MasterchainInfo;
liteServer.shardHash workchain:int32 id:int64 top_block_id:ton.BlockIdExt start_lt:int64 end_lt:int64 before_split:Bool before_merge:Bool want_split:Bool want_merge:Bool next_catchain_seqno:int32 next_validator_shard:int64 min_ref_mc_seqno:int32 gen_utime:int32 fees_collected:bytes funds_collected:bytes = liteServer.ShardHash;
liteServer.allShardsInfo min_shard_gen_utime:int32 max_shard_gen_utime:int32 shards:vector<liteServer.shardHash> = liteServer.AllShardsInfo;
liteServer.blockHeader id:ton.blockIdExt mode:int32 header_proof:bytes = liteServer.BlockHeader;
//@param node_id_short  int256
liteServer.signature node_id_short:bytes signature:bytes = liteServer.Signature;
liteServer.signatureSet validator_set_hash:int32 catchain_seqno:int32 signatures:vector<liteServer.signature> = liteServer.SignatureSet;
liteServer.blockLinkBack to_key_block:Bool from:ton.blockIdExt to:ton.blockIdExt dest_proof:bytes proof:bytes state_proof:bytes = liteServer.BlockLink;
liteServer.blockLinkForward to_key_block:Bool from:ton.blockIdExt to:ton.blockIdExt dest_proof:bytes config_proof:bytes signatures:liteServer.SignatureSet = liteServer.BlockLink;
liteServer.partialBlockProof complete:Bool from:ton.blockIdExt to:ton.blockIdExt steps:vector<liteServer.BlockLink> = liteServer.PartialBlockProof;
//@param account    int256 if mode & 1
//@param lt         int64  if mode & 2
//@param hash       int256 if mode & 4
liteServer.transactionId mode:int32 account:bytes lt:int64 hash:bytes = liteServer.TransactionId;
//@param account    int256
liteServer.transactionId3 account:bytes lt:int64 = liteServer.TransactionId3;
liteServer.blockTransactions id:ton.blockIdExt req_count:int32 incomplete:Bool ids:vector<liteServer.transactionId> proof:bytes = liteServer.BlockTransactions;
liteServer.messageAnycast depth:int32 rewrite_pfx:bytes = liteServer.MessageAnycast;
liteServer.messageAddressExtNone = liteServer.MessageAddressExt;
liteServer.messageAddressExtSome len:int32 external_address:bytes = liteServer.MessageAddressExt;
//@param address    int256
liteServer.messageAddressIntStd workchain:int32 address:bytes = liteServer.MessageAddressInt;
//@param address    int256
liteServer.messageAddressIntStdAnycast anycast:liteServer.MessageAnycast workchain:int32 address:bytes = liteServer.MessageAddressInt;
liteServer.messageAddressIntVar workchain:int32 addr_len:int32 address:bytes = liteServer.MessageAddressInt;
liteServer.messageAddressIntVarAnycast anycast:liteServer.MessageAnycast workchain:int32 addr_len:int32 address:bytes = liteServer.MessageAddressInt;
//@param value              int256
//@param ihr_fee            int256
//@param fwd_fee            int256
liteServer.messageInfoInt
    ihr_disabled:Bool
    bounce:Bool
    bounced:Bool
    src:liteServer.MessageAddressInt
    dest:liteServer.MessageAddressInt
    value:bytes
    ihr_fee:bytes
    fwd_fee:bytes
    created_lt:int64
    created_at:int32 = liteServer.MessageInfo;
//@param import_fee         int256
liteServer.messageInfoExtIn src:liteServer.MessageAddressExt dest:liteServer.MessageAddressInt import_fee:bytes = liteServer.MessageInfo;
liteServer.messageInfoExtOut src:liteServer.MessageAddressInt dest:liteServer.MessageAddressExt created_lt:int64 created_at:int32 = liteServer.MessageInfo;
//@param bytes              int256
liteServer.message hash:bytes info:liteServer.MessageInfo init:bytes body:bytes = liteServer.Message;
//@param cells              int256
//@param bits               int256
liteServer.storageUsedShort cells:bytes bits:bytes = liteServer.StorageUsedShort;
//@param cells          int256
//@param bits           int256
//@param public_cells   int256
liteServer.storageUsed
    cells:bytes
    bits:bytes
    public_cells:bytes = liteServer.StorageUsed;
liteServer.currencyCollectionItem currency:int32 value:bytes = liteServer.CurrencyCollectionItem;
//@param grams              int256
liteServer.currencyCollection grams:bytes other:vector<liteServer.currencyCollectionItem> = liteServer.CurrencyCollection;
//@param old_hash           int256
//@param new_hash           int256
liteServer.hashUpdate old_hash:bytes new_hash:bytes = liteServer.HashUpdate;
//@param storage_fees_collected int256
//@param storage_fees_due       maybe int256 (empty bytes on null)
liteServer.transactionStoragePhase
    storage_fees_collected:bytes
    has_storage_fees_due:Bool
    storage_fees_due:bytes
    status_change:int32 = liteServer.TransactionStoragePhase;
//@param due_fees_collected     maybe int256 (empty bytes on null)
liteServer.transactionCreditPhase
    has_due_fees_collected:Bool
    due_fees_collected:bytes
    credit:liteServer.CurrencyCollection = liteServer.TransactionCreditPhase;
//@param reason             0 -> no_state, 1 -> bad_state, 2 -> no_gas
liteServer.transactionComputePhaseSkipped reason:int32 = liteServer.TransactionComputePhase;
//@param gas_fees               int256
//@param gas_used               int256
//@param gas_limit              int256
//@param gas_credit             maybe int256 (empty on null)
//@param vm_init_state_hash     int256
//@param vm_final_state_hash    int256
liteServer.transactionComputePhaseVm
    success:Bool
    msg_state_used:Bool
    account_activated:Bool
    gas_fees:bytes
    gas_used:bytes
    gas_limit:bytes
    has_gas_credit:Bool
    gas_credit:bytes
    mode:int32
    exit_code:int32
    has_exit_arg:Bool
    exit_arg:int32
    vm_steps:int32
    vm_init_state_hash:bytes
    vm_final_state_hash:bytes = liteServer.TransactionComputePhase;
liteServer.transactionActionPhase
    success:Bool
    valid:Bool
    no_funds:Bool
    status_change:int32
    has_total_fwd_fees:Bool
    total_fwd_fees:bytes
    has_total_action_fees:Bool
    total_action_fees:bytes
    result_code:int32
    has_result_arg:Bool
    result_arg:int32
    tot_actions:int32
    spec_actions:int32
    skipped_actions:int32
    msgs_created:int32
    action_list_hash:bytes
    tot_msg_size:liteServer.StorageUsedShort = liteServer.TransactionActionPhase;
liteServer.transactionBouncePhaseNegFunds = liteServer.TransactionBouncePhase;
//@param req_fwd_fees   int256
liteServer.transactionBouncePhaseNoFunds
    msg_size:liteServer.StorageUsedShort
    req_fwd_fees:bytes = liteServer.TransactionBouncePhase;
//@param msg_fees       int256
//@param fwd_fees       int256
liteServer.transactionBouncePhaseOk
    msg_size:liteServer.StorageUsedShort
    msg_fees:bytes
    fwd_fees:bytes = liteServer.TransactionBouncePhase;
//@param code               -1 -> success,
//                          0 -> no elections or wrong sender workchain,
//                          1 -> invalid signature
//                          2 -> stake is too small relative to others
//                          3 -> invalid election id
//                          4 -> already sent stake with different pubkey
//                          5 -> stake is too small
//                          6 -> max-factor < 1
//@param pubkey             int256
//@param adnl_addr          int256
liteServer.transactionAdditionalInfoStakeSend status:int32 pubkey:bytes elect_time:int32 max_factor:int32 adnl_addr:bytes = liteServer.TransactionAdditionalInfo;
liteServer.transactionAdditionalInfoStakeRecover success:Bool = liteServer.TransactionAdditionalInfo;
liteServer.transactionDescrOrdinary
    credit_first:Bool
    storage_ph:liteServer.TransactionStoragePhase
    credit_ph:liteServer.TransactionCreditPhase
    compute_ph:liteServer.TransactionComputePhase
    action:liteServer.TransactionActionPhase
    aborted:Bool
    bounce:liteServer.TransactionBouncePhase
    destroyed:Bool
    additional:liteServer.TransactionAdditionalInfo = liteServer.TransactionDescr;
liteServer.transactionDescrStorage
    storage_ph:liteServer.TransactionStoragePhase = liteServer.TransactionDescr;
liteServer.transactionDescrTickTock
    is_tock:Bool
    storage_ph:liteServer.TransactionStoragePhase
    compute_ph:liteServer.TransactionComputePhase
    action:liteServer.TransactionActionPhase
    aborted:Bool
    destroyed:Bool = liteServer.TransactionDescr;
liteServer.transactionDescrSplitPrepare
    storage_ph:liteServer.TransactionStoragePhase
    compute_ph:liteServer.TransactionComputePhase
    action:liteServer.TransactionActionPhase
    aborted:Bool
    destroyed:Bool = liteServer.TransactionDescr;
liteServer.transactionDescrSplitInstall
    installed:Bool = liteServer.TransactionDescr;
liteServer.transactionDescrMergePrepare
    storage_ph:liteServer.TransactionStoragePhase
    aborted:Bool = liteServer.TransactionDescr;
liteServer.transactionDescrMergeInstall
    storage_ph:liteServer.TransactionStoragePhase
    credit_ph:liteServer.TransactionCreditPhase
    compute_ph:liteServer.TransactionComputePhase
    action:liteServer.TransactionActionPhase
    aborted:Bool
    destroyed:Bool = liteServer.TransactionDescr;
//@param account            int256
//@param prev_trans_hash    int256
//@param total_fees         int256
liteServer.transaction
    workchain:int32
    account:bytes
    hash:bytes
    lt:int64
    prev_trans_hash:bytes
    prev_trans_lt:int64
    now:int32
    outmsg_cnt:int32
    orig_status:int32
    end_status:int32
    in_msg:liteServer.Message
    out_msgs:vector<liteServer.message>
    total_fees:bytes
    hash_update:liteServer.HashUpdate
    desc:liteServer.TransactionDescr = liteServer.Transaction;
liteServer.transactionList ids:vector<ton.blockIdExt> transactions:vector<liteServer.transaction> = liteServer.TransactionList;
liteServer.globalVersion version:int32 capabilities:int64 = liteServer.GlobalVersion;
//@param root_hash  int256
//@param file_hash  int256
liteServer.extBlockRef end_lt:int64 seqno:int32 root_hash:bytes file_hash:bytes = liteServer.ExtBlockRef;
liteServer.blockInfo
    version:int32
    not_master:Bool
    after_merge:Bool
    before_split:Bool
    after_split:Bool
    want_split:Bool
    want_merge:Bool
    key_block:Bool
    vert_seqno_incr:Bool
    flags:int32
    seq_no:int32
    vert_seq_no:int32
    gen_utime:int32
    start_lt:int64
    end_lt:int64
    gen_validator_list_hash_short:int32
    gen_catchain_seqno:int32
    min_ref_mc_seqno:int32
    prev_key_block_seqno:int32
    gen_software:liteServer.GlobalVersion
    master_ref:liteServer.ExtBlockRef = liteServer.BlockInfo;
liteServer.valueFlow
    from_prev_blk:liteServer.CurrencyCollection
    to_next_blk:liteServer.CurrencyCollection
    imported:liteServer.CurrencyCollection
    exported:liteServer.CurrencyCollection
    fees_collected:liteServer.CurrencyCollection
    fees_imported:liteServer.CurrencyCollection
    recovered:liteServer.CurrencyCollection
    created:liteServer.CurrencyCollection
    minted:liteServer.CurrencyCollection = liteServer.ValueFlow;
//@param id             int256
//@param fees_collected int256
liteServer.inMsgDescrItem
    id:bytes
    fees_collected:bytes
    value_imported:liteServer.CurrencyCollection = liteServer.InMsgDescrItem;
liteServer.outMsgDescrItem
    id:bytes
    value:liteServer.CurrencyCollection = liteServer.OutMsgDescrItem;
//@param addr   int256
liteServer.blockExtraAccount
    addr:bytes
    transaction_cnt:int32
    state_update:liteServer.HashUpdate = liteServer.BlockExtraAccount;
liteServer.shardFeesItem
    fees:liteServer.CurrencyCollection
    create:liteServer.CurrencyCollection = liteServer.ShardFeesItem;
liteServer.mcBlockExtra
    key_block:Bool
    shard_hashes:liteServer.AllShardsInfo
    config:liteServer.ConfigInfo = liteServer.McBlockExtra;
//@param rand_seed      int256
//@param created_by     int256
liteServer.blockExtra
    in_msg_descr:vector<liteServer.inMsgDescrItem>
    out_msg_descr:vector<liteServer.outMsgDescrItem>
    accounts:vector<liteServer.blockExtraAccount>
    rand_seed:bytes
    created_by:bytes
    custom:liteServer.McBlockExtra = liteServer.BlockExtra;
liteServer.block
    id:ton.BlockIdExt
    masterchain_id:ton.BlockIdExt
    global_id:int32
    info:liteServer.BlockInfo
    value_flow:liteServer.ValueFlow
    block_extra:liteServer.BlockExtra
    previous:vector<ton.blockIdExt>
    next:vector<ton.blockId>
    transactions:vector<liteServer.transaction> = liteServer.Block;
liteServer.validator pubkey:bytes adnl_addr:bytes weight:int64 cum_weight:int64 = liteServer.Validator;
liteServer.validatorSet
    utime_since:int32
    utime_until:int32
    total:int32
    main:int32
    total_weight:int64
    list:vector<liteServer.validator> = liteServer.ValidatorSet;
//@param due_payment    maybe int256 (empty on null)
liteServer.storageInfo
    storage_used:liteServer.StorageUsed
    last_paid:int32
    has_due_payment:Bool
    due_payment:bytes = liteServer.StorageInfo;
liteServer.accountStateUninit = liteServer.AccountState;
//@param key    int256
liteServer.simpleLib key:bytes is_public:Bool root:bytes  = liteServer.SimpleLib;
liteServer.tickTock tick:Bool tock:Bool = liteServer.TickTock;
liteServer.accountStateActive
    has_split_depth:Bool
    split_depth:int32
    special:liteServer.TickTock
    has_code:Bool
    code:bytes
    has_data:Bool
    data:bytes
    library:vector<liteServer.simpleLib> = liteServer.AccountState;
//@param state_hash         int256
liteServer.accountStateFrozen state_hash:bytes = liteServer.AccountState;
//@param addr               int256
//@param last_trans_hash    int256
liteServer.account
    addr:liteServer.MessageAddressInt
    storage_stat:liteServer.StorageInfo
    last_trans_lt:int64
    last_trans_hash:bytes
    balance:liteServer.CurrencyCollection
    state:liteServer.AccountState = liteServer.Account;
liteServer.blockState
    utime:int32
    lt:int64
    total_balance:liteServer.CurrencyCollection
    total_validator_fees:liteServer.CurrencyCollection
    global_balance:liteServer.CurrencyCollection
    accounts:vector<liteServer.account> = liteServer.BlockState;

liteServer.configMintPrice mint_new_price:bytes mint_add_price:bytes = liteServer.ConfigMintPrice;
liteServer.configToMint currency_collection:vector<liteServer.currencyCollectionItem> = liteServer.ConfigToMint;
liteServer.configParams ids:vector<int32> = liteServer.ConfigParams;
liteServer.configProposalSetup min_tot_rounds:int32 max_tot_rounds:int32 min_wins:int32 max_losses:int32 min_store_sec:int32 max_store_sec:int32 bit_price:int32 cell_price:int32 = liteServer.ConfigProposalSetup;
liteServer.configVotingSetup normal_params:liteServer.ConfigProposalSetup critical_params:liteServer.ConfigProposalSetup = liteServer.ConfigVotingSetup;
liteServer.configWorkchainFormat vm_version:int32 vm_mode:int64 = liteServer.ConfigWorkchainFormat;
liteServer.configWorkchainInfo
    enabled_since:int32
    actual_min_split:int32
    min_split:int32
    max_split:int32
    basic:Bool
    active:Bool
    accept_msgs:Bool
    flags:int32
    zerostate_root_hash:bytes
    zerostate_file_hash:bytes
    version:int32
    format:liteServer.ConfigWorkchainFormat = liteServer.ConfigWorkchainInfo;
liteServer.configWorkchains workchains:vector<liteServer.configWorkchainInfo> = liteServer.ConfigWorkchains;
//@param deposit            int256
//@param bit_price          int256
//@param cell_price         int256
liteServer.configComplaintPricing deposit:bytes bit_price:bytes cell_price:bytes = liteServer.ConfigComplaintPricing;
//@param masterchain_block_fee  int256
//@param basechain_block_fee    int256
liteServer.configBlockCreateFees masterchain_block_fee:bytes basechain_block_fee:bytes = liteServer.ConfigBlockCreateFees;
liteServer.configValidatorsTimings validators_elected_for:int32 elections_start_before:int32 elections_end_before:int32 stake_held_for:int32 = liteServer.ConfigValidatorsTimings;
liteServer.configValidatorsQuantityLimits max_validators:int32 max_main_validators:int32 min_validators:int32 = liteServer.ConfigValidatorsQuantityLimits;
//@param min_stake          int256
//@param max_stake          int256
//@param min_total_stake    int256
liteServer.configValidatorsStakeLimits min_stake:bytes max_stake:bytes min_total_stake:bytes max_stake_factor:int32 = liteServer.ConfigValidatorsStakeLimits;
liteServer.configStoragePrice utime_since:int32 bit_price_ps:int64 cell_price_ps:int64 mc_bit_price_ps:int64 mc_cell_price_ps:int64 = liteServer.ConfigStoragePrice;
liteServer.configStoragePrices prices:vector<liteServer.configStoragePrice> = liteServer.ConfigStoragePrices;
liteServer.configGasPrices
    gas_price:int64
    gas_limit:int64
    gas_credit:int64
    block_gas_limit:int64
    freeze_due_limit:int64
    delete_due_limit:int64 = liteServer.ConfigGasLimitsPrices;
liteServer.configGasPricesExt
    gas_price:int64
    gas_limit:int64
    special_gas_limit:int64
    gas_credit:int64
    block_gas_limit:int64
    freeze_due_limit:int64
    delete_due_limit:int64 = liteServer.ConfigGasLimitsPrices;
liteServer.configGasFlatPfx
    flat_gas_limit:int64
    flat_gas_price:int64
    other:liteServer.ConfigGasLimitsPrices = liteServer.ConfigGasLimitsPrices;
liteServer.configParamLimits underload:int32 soft_limit:int32 hard_limit:int32 = liteServer.ConfigParamLimits;
liteServer.configBlockLimits
    bytes:liteServer.ConfigParamLimits
    gas:liteServer.ConfigParamLimits
    lt_delta:liteServer.ConfigParamLimits = liteServer.ConfigBlockLimits;
liteServer.configMsgForwardPrices
    lump_price:int64
    bit_price:int64
    cell_price:int64
    ihr_price_factor:int64
    first_frac:int32
    next_frac:int32 = liteServer.ConfigMsgForwardPrices;
liteServer.configCatchainConfigRegular
    mc_catchain_lifetime:int32
    shard_catchain_lifetime:int32
    shard_validators_lifetime:int32
    shard_validators_num:int32 = liteServer.ConfigCatchainConfig;
liteServer.configCatchainConfigNew
    flags:int32
    shuffle_mc_validators:Bool
    mc_catchain_lifetime:int32
    shard_catchain_lifetime:int32
    shard_validators_lifetime:int32
    shard_validators_num:int32 = liteServer.ConfigCatchainConfig;
liteServer.configConsensusConfigRegular
    round_candidates:int32
    next_candidate_delay_ms:int32
    consensus_timeout_ms:int32
    fast_attempts:int32
    attempt_duration:int32
    catchain_max_deps:int32
    max_block_bytes:int32
    max_collated_bytes:int32 = liteServer.ConfigConsensusConfig;
liteServer.configConsensusConfigNew
    flags:int32
    new_catchain_ids:Bool
    round_candidates:int32
    next_candidate_delay_ms:int32
    consensus_timeout_ms:int32
    fast_attempts:int32
    attempt_duration:int32
    catchain_max_deps:int32
    max_block_bytes:int32
    max_collated_bytes:int32 = liteServer.ConfigConsensusConfig;
liteServer.configFundamentalSmcAddresses
    addresses:vector<liteServer.accountId> = liteServer.ConfigFundamentalSmcAddresses;
liteServer.configInfo
    config_addr:liteServer.AccountId
    elector_addr:liteServer.AccountId
    minter_addr:liteServer.AccountId
    fee_collector_addr:liteServer.AccountId
    dns_root_addr:liteServer.AccountId
    mint_price:liteServer.ConfigMintPrice
    to_mint:liteServer.configToMint
    global_version:liteServer.GlobalVersion
    mandatory_params:liteServer.ConfigParams
    critical_params:liteServer.ConfigParams
    config_voting_setup:liteServer.ConfigVotingSetup
    workchains:liteServer.ConfigWorkchains
    complaint_pricing:liteServer.ConfigComplaintPricing
    block_create_fees:liteServer.ConfigBlockCreateFees
    validators_timings:liteServer.ConfigValidatorsTimings
    validators_quantity_limits:liteServer.ConfigValidatorsQuantityLimits
    validators_stake_limits:liteServer.ConfigValidatorsStakeLimits
    storage_prices:liteServer.ConfigStoragePrices
    masterchain_gas_prices:liteServer.ConfigGasLimitsPrices
    basechain_gas_prices:liteServer.ConfigGasLimitsPrices
    masterchain_block_limits:liteServer.ConfigBlockLimits
    basechain_block_limits:liteServer.ConfigBlockLimits
    masterchain_msg_forward_prices:liteServer.ConfigMsgForwardPrices
    basechain_msg_forward_prices:liteServer.ConfigMsgForwardPrices
    catchain_config:liteServer.ConfigCatchainConfig
    consensus_config:liteServer.ConfigConsensusConfig
    fundamental_smc_addresses:liteServer.ConfigFundamentalSmcAddresses
    prev_vset:liteServer.ValidatorSet
    prev_temp_vset:liteServer.ValidatorSet
    curr_vset:liteServer.ValidatorSet
    cur_temp_vset:liteServer.ValidatorSet
    next_vset:liteServer.ValidatorSet
    next_temp_vset:liteServer.ValidatorSet = liteServer.ConfigInfo;
//@param vset_hash      int256
//@param total_stake    int256
liteServer.pastElectionsItem
    election_id:int32
    unfreeze_at:int32
    stake_held_for:int32
    vset_hash:bytes
    total_stake:bytes
    total_bonuses:bytes = liteServer.PastElectionsItem;
liteServer.pastElections
    elections:vector<liteServer.pastElectionsItem> = liteServer.PastElections;

---functions---

init options:options = options.Info;
close = Ok;

options.setConfig config:config = options.ConfigInfo;
options.validateConfig config:config = options.ConfigInfo;

createNewKey local_password:secureBytes mnemonic_password:secureBytes random_extra_seed:secureBytes = Key;
deleteKey key:key = Ok;
deleteAllKeys = Ok;
exportKey input_key:InputKey = ExportedKey;
exportPemKey input_key:InputKey key_password:secureBytes = ExportedPemKey;
exportEncryptedKey input_key:InputKey key_password:secureBytes = ExportedEncryptedKey;
exportUnencryptedKey input_key:InputKey = ExportedUnencryptedKey;
importKey local_password:secureBytes mnemonic_password:secureBytes exported_key:exportedKey = Key;
importPemKey local_password:secureBytes key_password:secureBytes exported_key:exportedPemKey = Key;
importEncryptedKey local_password:secureBytes key_password:secureBytes exported_encrypted_key:exportedEncryptedKey = Key;
importUnencryptedKey local_password:secureBytes  exported_unencrypted_key:exportedUnencryptedKey = Key;
changeLocalPassword input_key:InputKey new_local_password:secureBytes = Key;

generateKeyPair = Key;

encrypt decrypted_data:secureBytes secret:secureBytes = Data;
decrypt encrypted_data:secureBytes secret:secureBytes = Data;
kdf password:secureBytes salt:secureBytes iterations:int32 = Data;

unpackAccountAddress account_address:string = UnpackedAccountAddress;
packAccountAddress account_address:unpackedAccountAddress = AccountAddress;
getBip39Hints prefix:string = Bip39Hints;

//raw.init initial_account_state:raw.initialAccountState = Ok;
raw.getAccountState account_address:accountAddress = raw.FullAccountState;
raw.getTransactions private_key:InputKey account_address:accountAddress from_transaction_id:internal.transactionId = raw.Transactions;
raw.sendMessage body:bytes  = Ok;
raw.createAndSendMessage destination:accountAddress initial_account_state:bytes data:bytes = Ok;
raw.createQuery destination:accountAddress init_code:bytes init_data:bytes body:bytes = query.Info;
raw.createQueryTvc destination:accountAddress init_state:bytes body:bytes = query.Info;

sync = ton.BlockIdExt;

// revision = 0 -- use default revision
// revision = x (x > 0) -- use revision x
// revision = -1 -- use experimental (newest) revision. Only for debug purpose
//
// workchain_id = -1 or 0. -1 for masterchain, 0 for basechain
// NB: use wallet_id = default_wallet_id + workchain_id
getAccountAddress initial_account_state:InitialAccountState revision:int32 workchain_id:int32 = AccountAddress;
guessAccountRevision initial_account_state:InitialAccountState workchain_id:int32 = AccountRevisionList;

guessAccount public_key:string rwallet_init_public_key:string = AccountRevisionList;

getAccountState account_address:accountAddress = FullAccountState;
createQuery private_key:InputKey address:accountAddress timeout:int32 action:Action initial_account_state:InitialAccountState = query.Info;

computeLastBlockIds top_blocks:vector<ton.blockId> = ton.BlockIds;

findTransaction account_address:accountAddress message_id:bytes after:int32 = TransactionSearchResult;

msg.decrypt input_key:InputKey data:msg.dataEncryptedArray = msg.DataDecryptedArray;
msg.decryptWithProof proof:bytes data:msg.dataEncrypted = msg.Data;

query.send id:int53 = Ok;
query.forget id:int53 = Ok;
query.estimateFees id:int53 ignore_chksig:Bool = query.Fees;
// query.emulate id:int53 ignore_chksig:Bool = query.EmulationResult;
query.getInfo id:int53 = query.Info;

smc.load account_address:accountAddress = smc.Info;
//smc.forget id:int53 = Ok;
smc.getCode id:int53 = tvm.Cell;
smc.getData id:int53 = tvm.Cell;
smc.getState id:int53 = tvm.Cell;
smc.runGetMethod id:int53 method:smc.MethodId stack:vector<tvm.StackEntry> = smc.RunResult;

ftabi.computeFunctionId signature:ftabi.FunctionSignature = ftabi.FunctionId;
ftabi.computeFunctionSignature name:string inputs:vector<ftabi.Param> outputs:vector<ftabi.Param> = ftabi.FunctionSignature;
ftabi.createFunction name:string header:vector<ftabi.NamedParam> inputs:vector<ftabi.Param> outputs:vector<ftabi.Param> = ftabi.Function;
ftabi.getFunction abi:string name:string = ftabi.Function;
ftabi.createMessageBody function:ftabi.Function call:ftabi.FunctionCall = ftabi.MessageBody;
ftabi.runLocal address:AccountAddress function:ftabi.Function call:ftabi.FunctionCall = ftabi.DecodedOutput;
ftabi.decodeOutput function:ftabi.Function data:bytes = ftabi.DecodedOutput;
ftabi.decodeInput function:ftabi.Function data:bytes internal:Bool = ftabi.DecodedInput;
ftabi.generateStateInit tvc:bytes public_key:string = ftabi.StateInit;

//ftabi.jsonCreateMessageBody abi_call:string = ftabi.MessageBody;
//ftabi.jsonRunLocal address:AccountAddress abi_call:string = ftabi.JsonDecodedOutput;
//ftabi.jsonDecodeOutput abi:string data:bytes = ftabi.JsonDecodedOutput;
//ftabi.jsonDecodeInput abi:string data:bytes internal:Bool = ftabi.JsonDecodedInput;

dns.resolve account_address:accountAddress name:string category:int32 ttl:int32 = dns.Resolved;

pchan.signPromise input_key:InputKey promise:pchan.promise = pchan.Promise;
pchan.validatePromise public_key:bytes promise:pchan.promise = Ok;

pchan.packPromise promise:pchan.promise = Data;
pchan.unpackPromise data:secureBytes = pchan.Promise;

onLiteServerQueryResult id:int64 bytes:bytes = Ok;
onLiteServerQueryError id:int64 error:error = Ok;

withBlock id:ton.blockIdExt function:Function = Object;

runTests dir:string = Ok;

liteServer.getInfo = liteServer.Info;
liteServer.getTime = liteServer.CurrentTime;
liteServer.getMasterchainInfo = liteServer.MasterchainInfo;
liteServer.getState id:ton.blockIdExt = liteServer.BlockState;
liteServer.getBlock id:ton.blockIdExt = liteServer.Block;
liteServer.getBlockHeader id:ton.blockIdExt mode:int32 = liteServer.BlockHeader;
liteServer.getAccount id:ton.blockIdExt account:liteServer.accountId = liteServer.Account;
liteServer.getOneTransaction id:ton.blockIdExt account:liteServer.accountId lt:int64 = liteServer.Transaction;
//@param hash   int256
liteServer.getTransactions count:int32 account:liteServer.accountId lt:int64 hash:bytes = liteServer.TransactionList;
//@param lt     int64 if mode & 2
//@param utime  int32 if mode & 4
liteServer.lookupBlock mode:int32 id:ton.blockId lt:int64 utime:int32 = liteServer.Block;
//@param after  liteServer.transactionId3 if mode & 128
liteServer.listBlockTransactions id:ton.blockIdExt mode:int32 count:int32 after:liteServer.transactionId3 reverse_order:Bool want_proof:Bool = liteServer.BlockTransactions;
//@param target_block   ton.blockIdExt if mode & 1
liteServer.getBlockProof mode:int32 known_block:ton.blockIdExt target_block:ton.blockIdExt = liteServer.PartialBlockProof;
liteServer.getConfigAll id:ton.blockIdExt = liteServer.ConfigInfo;
liteServer.getConfigParams mode:int32 id:ton.blockIdExt param_list:vector<int32> = liteServer.ConfigInfo;
//@param bytes  int256
liteServer.getPastElections id:ton.BlockIdExt elector_addr:bytes = liteServer.PastElections;

//@description Sets new log stream for internal logging of tonlib. This is an offline method. Can be called before authorization. Can be called synchronously @log_stream New log stream
setLogStream log_stream:LogStream = Ok;

//@description Returns information about currently used log stream for internal logging of tonlib. This is an offline method. Can be called before authorization. Can be called synchronously
getLogStream = LogStream;

//@description Sets the verbosity level of the internal logging of tonlib. This is an offline method. Can be called before authorization. Can be called synchronously
//@new_verbosity_level New value of the verbosity level for logging. Value 0 corresponds to fatal errors, value 1 corresponds to errors, value 2 corresponds to warnings and debug warnings, value 3 corresponds to informational, value 4 corresponds to debug, value 5 corresponds to verbose debug, value greater than 5 and up to 1023 can be used to enable even more logging
setLogVerbosityLevel new_verbosity_level:int32 = Ok;

//@description Returns current verbosity level of the internal logging of tonlib. This is an offline method. Can be called before authorization. Can be called synchronously
getLogVerbosityLevel = LogVerbosityLevel;

//@description Returns list of available tonlib internal log tags, for example, ["actor", "binlog", "connections", "notifications", "proxy"]. This is an offline method. Can be called before authorization. Can be called synchronously
getLogTags = LogTags;

//@description Sets the verbosity level for a specified tonlib internal log tag. This is an offline method. Can be called before authorization. Can be called synchronously
//@tag Logging tag to change verbosity level @new_verbosity_level New verbosity level; 1-1024
setLogTagVerbosityLevel tag:string new_verbosity_level:int32 = Ok;

//@description Returns current verbosity level for a specified tonlib internal log tag. This is an offline method. Can be called before authorization. Can be called synchronously @tag Logging tag to change verbosity level
getLogTagVerbosityLevel tag:string = LogVerbosityLevel;

//@description Adds a message to tonlib internal log. This is an offline method. Can be called before authorization. Can be called synchronously
//@verbosity_level Minimum verbosity level needed for the message to be logged, 0-1023 @text Text of a message to log
addLogMessage verbosity_level:int32 text:string = Ok;
