package lib

import (
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/golang/glog"
)

type Postgres struct {
	db *pg.DB
}

func NewPostgres(db *pg.DB) *Postgres {
	// Print all queries.
	//db.AddQueryHook(pgdebug.DebugHook{
	//	Verbose: true,
	//})

	return &Postgres{
		db: db,
	}
}

func LogSelect(query *orm.Query) error {
	selectQuery := orm.NewSelectQuery(query)
	fmter := orm.NewFormatter().WithModel(selectQuery)
	queryStr, _ := selectQuery.AppendQuery(fmter, nil)
	glog.Info(string(queryStr))
	return query.Select()
}

//
// Tables
//
// When we can, we use unique fields (or combinations of unique fields) as the primary keys on the models.
// This lets us use the WherePK() query while also minimizing columns and indicies on disk.
//

type Chain struct {
	Name    string `pg:",pk"`
	TipHash *BlockHash
}

// Block represents BlockNode and MsgBitCloutHeader
type Block struct {
	// BlockNode and MsgBitCloutHeader
	Hash       *BlockHash `pg:",pk,unique"`
	ParentHash *BlockHash
	Height     uint64 `pg:",use_zero"`

	// BlockNode
	DifficultyTarget *BlockHash
	CumWork          *BlockHash
	Status           BlockStatus // TODO: Refactor

	// MsgBitCloutHeader
	TxMerkleRoot *BlockHash
	Version      uint32 `pg:",use_zero"`
	Timestamp    uint64 `pg:",use_zero"`
	Nonce        uint64 `pg:",use_zero"`
	ExtraNonce   uint64 `pg:",use_zero"`

	// Notifications
	Notified bool `pg:",use_zero"`
}

// Transaction represents MsgBitCloutTxn
type Transaction struct {
	Hash      *BlockHash `pg:",pk"`
	BlockHash *BlockHash
	Type      TxnType
	PublicKey []byte
	ExtraData map[string][]byte
	R         *BlockHash
	S         *BlockHash

	// Relationships
	Outputs                     []*TransactionOutput         `pg:"rel:has-many,join_fk:output_hash"`
	MetadataBlockReward         *MetadataBlockReward         `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataBitcoinExchange     *MetadataBitcoinExchange     `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataPrivateMessage      *MetadataPrivateMessage      `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataSubmitPost          *MetadataSubmitPost          `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataUpdateExchangeRate  *MetadataUpdateExchangeRate  `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataUpdateProfile       *MetadataUpdateProfile       `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataFollow              *MetadataFollow              `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataLike                *MetadataLike                `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataCreatorCoin         *MetadataCreatorCoin         `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataCreatorCoinTransfer *MetadataCreatorCoinTransfer `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataSwapIdentity        *MetadataSwapIdentity        `pg:"rel:belongs-to,join_fk:transaction_hash"`
}

// TransactionOutput represents BitCloutOutput, BitCloutInput, and UtxoEntry
type TransactionOutput struct {
	OutputHash  *BlockHash `pg:",pk"`
	OutputIndex uint32     `pg:",pk,use_zero"`
	OutputType  UtxoType   `pg:",use_zero"`
	PublicKey   []byte
	AmountNanos uint64 `pg:",use_zero"`
	Spent       bool   `pg:",use_zero"`
	InputHash   *BlockHash
	InputIndex  uint32 `pg:",pk,use_zero"`
}

// MetadataBlockReward represents BlockRewardMetadataa
type MetadataBlockReward struct {
	TransactionHash *BlockHash `pg:",pk"`
	ExtraData       []byte
}

// MetadataBitcoinExchange represents BitcoinExchangeMetadata
type MetadataBitcoinExchange struct {
	TransactionHash   *BlockHash `pg:",pk"`
	BitcoinBlockHash  *BlockHash
	BitcoinMerkleRoot *BlockHash
	// Not storing BitcoinTransaction *wire.MsgTx
	// Not storing BitcoinMerkleProof []*merkletree.ProofPart
}

// MetadataPrivateMessage represents PrivateMessageMetadata
type MetadataPrivateMessage struct {
	TransactionHash    *BlockHash `pg:",pk"`
	RecipientPublicKey []byte
	EncryptedText      []byte
	TimestampNanos     uint64
}

// MetadataSubmitPost represents SubmitPostMetadata
type MetadataSubmitPost struct {
	TransactionHash  *BlockHash `pg:",pk"`
	PostHashToModify *BlockHash
	ParentStakeID    *BlockHash
	Body             []byte
	TimestampNanos   uint64
	IsHidden         bool `pg:",use_zero"`
}

// MetadataUpdateExchangeRate represents UpdateBitcoinUSDExchangeRateMetadataa
type MetadataUpdateExchangeRate struct {
	TransactionHash    *BlockHash `pg:",pk"`
	USDCentsPerBitcoin uint64     `pg:",use_zero"`
}

// MetadataUpdateProfile represents UpdateProfileMetadata
type MetadataUpdateProfile struct {
	TransactionHash       *BlockHash `pg:",pk"`
	ProfilePublicKey      []byte
	NewUsername           []byte
	NewDescription        []byte
	NewProfilePic         []byte
	NewCreatorBasisPoints uint64 `pg:",use_zero"`
}

// MetadataFollow represents FollowMetadata
type MetadataFollow struct {
	TransactionHash   *BlockHash `pg:",pk"`
	FollowedPublicKey []byte
	IsUnfollow        bool `pg:",use_zero"`
}

// MetadataLike represents LikeMetadata
type MetadataLike struct {
	TransactionHash *BlockHash `pg:",pk"`
	LikedPostHash   *BlockHash
	IsUnlike        bool `pg:",use_zero"`
}

// MetadataCreatorCoin represents CreatorCoinMetadataa
type MetadataCreatorCoin struct {
	TransactionHash             *BlockHash `pg:",pk"`
	ProfilePublicKey            []byte
	OperationType               CreatorCoinOperationType `pg:",use_zero"`
	BitCloutToSellNanos         uint64                   `pg:",use_zero"`
	CreatorCoinToSellNanos      uint64                   `pg:",use_zero"`
	BitCloutToAddNanos          uint64                   `pg:",use_zero"`
	MinBitCloutExpectedNanos    uint64                   `pg:",use_zero"`
	MinCreatorCoinExpectedNanos uint64                   `pg:",use_zero"`
}

// MetadataCreatorCoinTransfer represents CreatorCoinTransferMetadataa
type MetadataCreatorCoinTransfer struct {
	TransactionHash            *BlockHash `pg:",pk"`
	ProfilePublicKey           []byte
	CreatorCoinToTransferNanos uint64 `pg:",use_zero"`
	ReceiverPublicKey          []byte
}

// MetadataSwapIdentity represents SwapIdentityMetadataa
type MetadataSwapIdentity struct {
	TransactionHash *BlockHash `pg:",pk"`
	FromPublicKey   []byte
	ToPublicKey     []byte
}

type Notification struct {
	TransactionHash *BlockHash `pg:",pk"`
	Mined           bool
	ToUser          []byte
	FromUser        []byte
	OtherUser       []byte
	Type            NotificationType
	Amount          uint64
	PostHash        *BlockHash
	Timestamp       uint64
}

type NotificationType uint8

const (
	NotificationUnknown NotificationType = iota
	NotificationSendClout
	NotificationLike
	NotificationFollow
	NotificationCoinPurchase
	NotificationCoinTransfer
	NotificationCoinDiamond
	NotificationPostMention
	NotificationPostReply
	NotificationPostReclout
)

type Profile struct {
	PKID                    *PKID `pg:",pk"`
	PublicKey               *PublicKey
	Username                string
	Description             string
	ProfilePic              []byte
	CreatorBasisPoints      uint64
	BitCloutLockedNanos     uint64
	NumberOfHolders         uint64
	CoinsInCirculationNanos uint64
	CoinWatermarkNanos      uint64
}

type Post struct {
	PostHash          *BlockHash `pg:",pk"`
	PosterPublicKey   []byte
	ParentPostHash    *BlockHash
	Body              string
	RecloutedPostHash *BlockHash
	QuotedReclout     bool
	Timestamp         uint64
	Hidden            bool
	LikeCount         uint64
	RecloutCount      uint64
	QuoteRecloutCount uint64
	DiamondCount      uint64
	CommentCount      uint64
	Pinned            bool
	ExtraData         map[string][]byte
}

func (post *Post) NewPostEntry() *PostEntry {
	postEntry := &PostEntry{
		PostHash:          post.PostHash,
		PosterPublicKey:   post.PosterPublicKey,
		Body:              []byte(post.Body),
		RecloutedPostHash: post.RecloutedPostHash,
		IsQuotedReclout:   post.QuotedReclout,
		TimestampNanos:    post.Timestamp,
		IsHidden:          post.Hidden,
		LikeCount:         post.LikeCount,
		RecloutCount:      post.RecloutCount,
		QuoteRecloutCount: post.QuoteRecloutCount,
		DiamondCount:      post.DiamondCount,
		CommentCount:      post.CommentCount,
		IsPinned:          post.Pinned,
		PostExtraData:     post.ExtraData,
	}

	if post.ParentPostHash != nil {
		postEntry.ParentStakeID = post.ParentPostHash.ToBytes()
	}

	return postEntry
}

func (post *Post) HasMedia() bool {
	bodyJSONObj := BitCloutBodySchema{}
	err := json.Unmarshal([]byte(post.Body), &bodyJSONObj)
	// Return true if body json can be parsed and ImageUrls is not nil/non-empty or EmbedVideoUrl is not nil/non-empty
	return (err == nil && len(bodyJSONObj.ImageURLs) > 0) || len(post.ExtraData["EmbedVideoURL"]) > 0
}

type Like struct {
	LikerPublicKey []byte     `pg:",pk"`
	LikedPostHash  *BlockHash `pg:",pk"`
}

func (like *Like) NewLikeEntry() *LikeEntry {
	return &LikeEntry{
		LikerPubKey:   like.LikerPublicKey,
		LikedPostHash: like.LikedPostHash,
	}
}

type Follow struct {
	FollowerPKID *PKID `pg:",pk,type:bytea"`
	FollowedPKID *PKID `pg:",pk,type:bytea"`
}

func (follow *Follow) NewFollowEntry() *FollowEntry {
	return &FollowEntry{
		FollowerPKID: follow.FollowerPKID,
		FollowedPKID: follow.FollowedPKID,
	}
}

type Diamond struct {
	SenderPKID      *PKID      `pg:",pk"`
	ReceiverPKID    *PKID      `pg:",pk"`
	DiamondPostHash *BlockHash `pg:",pk"`
	DiamondLevel    uint8
}

// TODO: This doesn't need to be a table. Just add sender to MetadataPrivateMessage?
// The only reason we might not want to do this is if we end up pruning Metadata tables.
type Message struct {
	MessageHash        *BlockHash `pg:",pk"`
	SenderPublicKey    []byte
	RecipientPublicKey []byte
	EncryptedText      []byte
	TimestampNanos     uint64
	// TODO: Version

	// Used to track deletions in the UtxoView
	isDeleted bool
}

type CreatorCoinBalance struct {
	HolderPKID   *PKID `pg:",pk"`
	CreatorPKID  *PKID `pg:",pk"`
	BalanceNanos uint64
	HasPurchased bool
}

func (balance *CreatorCoinBalance) NewBalanceEntry() *BalanceEntry {
	return &BalanceEntry{
		HODLerPKID:   balance.HolderPKID,
		CreatorPKID:  balance.CreatorPKID,
		BalanceNanos: balance.BalanceNanos,
		HasPurchased: balance.HasPurchased,
	}
}

//
// Blockchain and Transactions
//

func (postgres *Postgres) UpsertBlock(blockNode *BlockNode) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		return postgres.UpsertBlockTx(tx, blockNode)
	})
}

func (postgres *Postgres) UpsertBlockTx(tx *pg.Tx, blockNode *BlockNode) error {
	block := &Block{
		Hash:   blockNode.Hash,
		Height: blockNode.Header.Height,

		DifficultyTarget: blockNode.DifficultyTarget,
		CumWork:          BigintToHash(blockNode.CumWork),
		Status:           blockNode.Status,

		TxMerkleRoot: blockNode.Header.TransactionMerkleRoot,
		Version:      blockNode.Header.Version,
		Timestamp:    blockNode.Header.TstampSecs,
		Nonce:        blockNode.Header.Nonce,
		ExtraNonce:   blockNode.Header.ExtraNonce,
	}

	// The genesis block has a nil parent
	if blockNode.Parent != nil {
		block.ParentHash = blockNode.Parent.Hash
	}

	_, err := tx.Model(block).WherePK().OnConflict("(hash) DO UPDATE").Insert()
	return err
}

func (postgres *Postgres) GetBlockIndex() (map[BlockHash]*BlockNode, error) {
	var blocks []Block
	err := postgres.db.Model(&blocks).Select()
	if err != nil {
		return nil, err
	}

	blockMap := make(map[BlockHash]*BlockNode)
	for _, block := range blocks {
		blockMap[*block.Hash] = &BlockNode{
			Hash:             block.Hash,
			Height:           uint32(block.Height),
			DifficultyTarget: block.DifficultyTarget,
			CumWork:          HashToBigint(block.CumWork),
			Header: &MsgBitCloutHeader{
				Version:               block.Version,
				PrevBlockHash:         block.ParentHash,
				TransactionMerkleRoot: block.TxMerkleRoot,
				TstampSecs:            block.Timestamp,
				Height:                block.Height,
				Nonce:                 block.Nonce,
				ExtraNonce:            block.ExtraNonce,
			},
			Status: block.Status,
		}
	}

	// Setup parent pointers
	for _, blockNode := range blockMap {
		// Genesis block has nil parent
		parentHash := blockNode.Header.PrevBlockHash
		if parentHash != nil {
			blockNode.Parent = blockMap[*parentHash]
		}
	}

	return blockMap, nil
}

func (postgres *Postgres) GetChain(name string) *Chain {
	chain := &Chain{
		Name: name,
	}

	err := postgres.db.Model(chain).First()
	if err != nil {
		return nil
	}

	return chain
}

func (postgres *Postgres) UpsertChain(name string, tipHash *BlockHash) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		return postgres.UpsertChainTx(tx, name, tipHash)
	})
}

func (postgres *Postgres) UpsertChainTx(tx *pg.Tx, name string, tipHash *BlockHash) error {
	bestChain := &Chain{
		TipHash: tipHash,
		Name:    name,
	}

	_, err := tx.Model(bestChain).WherePK().OnConflict("(name) DO UPDATE").Insert()
	return err
}

func (postgres *Postgres) InsertTransactionsTx(tx *pg.Tx, bitCloutTxns []*MsgBitCloutTxn, blockHash *BlockHash) error {
	var transactions []*Transaction
	var transactionOutputs []*TransactionOutput
	var transactionInputs []*TransactionOutput
	var metadataBlockRewards []*MetadataBlockReward
	var metadataBitcoinExchanges []*MetadataBitcoinExchange
	var metadataPrivateMessages []*MetadataPrivateMessage
	var metadataSubmitPosts []*MetadataSubmitPost
	var metadataUpdateProfiles []*MetadataUpdateProfile
	var metadataExchangeRates []*MetadataUpdateExchangeRate
	var metadataFollows []*MetadataFollow
	var metadataLikes []*MetadataLike
	var metadataCreatorCoins []*MetadataCreatorCoin
	var metadataCreatorCoinTransfers []*MetadataCreatorCoinTransfer
	var metadataSwapIdentities []*MetadataSwapIdentity

	for _, txn := range bitCloutTxns {
		txnHash := txn.Hash()
		transaction := &Transaction{
			Hash:      txnHash,
			BlockHash: blockHash,
			Type:      txn.TxnMeta.GetTxnType(),
			PublicKey: txn.PublicKey,
			ExtraData: txn.ExtraData,
		}

		if txn.Signature != nil {
			transaction.R = BigintToHash(txn.Signature.R)
			transaction.S = BigintToHash(txn.Signature.S)
		}

		transactions = append(transactions, transaction)

		for i, input := range txn.TxInputs {
			transactionInputs = append(transactionInputs, &TransactionOutput{
				OutputHash:  &input.TxID,
				OutputIndex: input.Index,
				InputHash:   txnHash,
				InputIndex:  uint32(i),
				Spent:       true,
			})
		}

		for i, output := range txn.TxOutputs {
			transactionOutputs = append(transactionOutputs, &TransactionOutput{
				OutputHash:  txnHash,
				OutputIndex: uint32(i),
				OutputType:  0, // TODO
				PublicKey:   output.PublicKey,
				AmountNanos: output.AmountNanos,
			})
		}

		if txn.TxnMeta.GetTxnType() == TxnTypeUpdateGlobalParams {
			// No extra metadata needed
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			txMeta := txn.TxnMeta.(*BlockRewardMetadataa)
			metadataBlockRewards = append(metadataBlockRewards, &MetadataBlockReward{
				TransactionHash: txnHash,
				ExtraData:       txMeta.ExtraData,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
			txMeta := txn.TxnMeta.(*BitcoinExchangeMetadata)
			metadataBitcoinExchanges = append(metadataBitcoinExchanges, &MetadataBitcoinExchange{
				TransactionHash:   txnHash,
				BitcoinBlockHash:  txMeta.BitcoinBlockHash,
				BitcoinMerkleRoot: txMeta.BitcoinMerkleRoot,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
			txMeta := txn.TxnMeta.(*PrivateMessageMetadata)
			metadataPrivateMessages = append(metadataPrivateMessages, &MetadataPrivateMessage{
				TransactionHash:    txnHash,
				RecipientPublicKey: txMeta.RecipientPublicKey,
				EncryptedText:      txMeta.EncryptedText,
				TimestampNanos:     txMeta.TimestampNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
			txMeta := txn.TxnMeta.(*SubmitPostMetadata)

			postHashToModify := &BlockHash{}
			parentStakeId := &BlockHash{}
			copy(postHashToModify[:], txMeta.PostHashToModify)
			copy(parentStakeId[:], txMeta.ParentStakeID)

			metadataSubmitPosts = append(metadataSubmitPosts, &MetadataSubmitPost{
				TransactionHash:  txnHash,
				PostHashToModify: postHashToModify,
				ParentStakeID:    parentStakeId,
				Body:             txMeta.Body,
				TimestampNanos:   txMeta.TimestampNanos,
				IsHidden:         txMeta.IsHidden,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
			txMeta := txn.TxnMeta.(*UpdateProfileMetadata)
			metadataUpdateProfiles = append(metadataUpdateProfiles, &MetadataUpdateProfile{
				TransactionHash:       txnHash,
				ProfilePublicKey:      txMeta.ProfilePublicKey,
				NewUsername:           txMeta.NewUsername,
				NewProfilePic:         txMeta.NewProfilePic,
				NewCreatorBasisPoints: txMeta.NewCreatorBasisPoints,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateBitcoinUSDExchangeRate {
			txMeta := txn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)
			metadataExchangeRates = append(metadataExchangeRates, &MetadataUpdateExchangeRate{
				TransactionHash:    txnHash,
				USDCentsPerBitcoin: txMeta.USDCentsPerBitcoin,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
			txMeta := txn.TxnMeta.(*FollowMetadata)
			metadataFollows = append(metadataFollows, &MetadataFollow{
				TransactionHash:   txnHash,
				FollowedPublicKey: txMeta.FollowedPublicKey,
				IsUnfollow:        txMeta.IsUnfollow,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeLike {
			txMeta := txn.TxnMeta.(*LikeMetadata)
			metadataLikes = append(metadataLikes, &MetadataLike{
				TransactionHash: txnHash,
				LikedPostHash:   txMeta.LikedPostHash,
				IsUnlike:        txMeta.IsUnlike,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
			txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
			metadataCreatorCoins = append(metadataCreatorCoins, &MetadataCreatorCoin{
				TransactionHash:             txnHash,
				ProfilePublicKey:            txMeta.ProfilePublicKey,
				OperationType:               txMeta.OperationType,
				BitCloutToSellNanos:         txMeta.BitCloutToSellNanos,
				CreatorCoinToSellNanos:      txMeta.CreatorCoinToSellNanos,
				BitCloutToAddNanos:          txMeta.BitCloutToAddNanos,
				MinBitCloutExpectedNanos:    txMeta.MinBitCloutExpectedNanos,
				MinCreatorCoinExpectedNanos: txMeta.MinCreatorCoinExpectedNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoinTransfer {
			txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)
			metadataCreatorCoinTransfers = append(metadataCreatorCoinTransfers, &MetadataCreatorCoinTransfer{
				TransactionHash:            txnHash,
				ProfilePublicKey:           txMeta.ProfilePublicKey,
				CreatorCoinToTransferNanos: txMeta.CreatorCoinToTransferNanos,
				ReceiverPublicKey:          txMeta.ReceiverPublicKey,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeSwapIdentity {
			txMeta := txn.TxnMeta.(*SwapIdentityMetadataa)
			metadataSwapIdentities = append(metadataSwapIdentities, &MetadataSwapIdentity{
				TransactionHash: txnHash,
				FromPublicKey:   txMeta.FromPublicKey,
				ToPublicKey:     txMeta.ToPublicKey,
			})
		} else {
			return fmt.Errorf("InsertTransactionTx: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
		}
	}

	if len(transactions) > 0 {
		if _, err := tx.Model(&transactions).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(transactionOutputs) > 0 {
		if _, err := tx.Model(&transactionOutputs).Returning("NULL").OnConflict("(output_hash, output_index) DO UPDATE").Insert(); err != nil {
			return err
		}
	}

	if len(transactionInputs) > 0 {
		if _, err := tx.Model(&transactionInputs).WherePK().Column("input_hash", "input_index", "spent").Update(); err != nil {
			return err
		}
	}

	if len(metadataBlockRewards) > 0 {
		if _, err := tx.Model(&metadataBlockRewards).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataBitcoinExchanges) > 0 {
		if _, err := tx.Model(&metadataBitcoinExchanges).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataPrivateMessages) > 0 {
		if _, err := tx.Model(&metadataPrivateMessages).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataSubmitPosts) > 0 {
		if _, err := tx.Model(&metadataSubmitPosts).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataUpdateProfiles) > 0 {
		if _, err := tx.Model(&metadataUpdateProfiles).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataExchangeRates) > 0 {
		if _, err := tx.Model(&metadataExchangeRates).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataFollows) > 0 {
		if _, err := tx.Model(&metadataFollows).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataLikes) > 0 {
		if _, err := tx.Model(&metadataLikes).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoins) > 0 {
		if _, err := tx.Model(&metadataCreatorCoins).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoinTransfers) > 0 {
		if _, err := tx.Model(&metadataCreatorCoinTransfers).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataSwapIdentities) > 0 {
		if _, err := tx.Model(&metadataSwapIdentities).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) UpsertBlockAndTransactions(blockNode *BlockNode, bitcloutBlock *MsgBitCloutBlock) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		err := postgres.UpsertBlockTx(tx, blockNode)
		if err != nil {
			return err
		}

		blockHash := blockNode.Hash
		err = postgres.UpsertChainTx(tx, "main", blockHash)
		if err != nil {
			return err
		}

		err = postgres.InsertTransactionsTx(tx, bitcloutBlock.Txns, blockHash)
		if err != nil {
			return err
		}

		return nil
	})
}

func (postgres *Postgres) GetUtxoEntryForUtxoKey(utxoKey *UtxoKey) *UtxoEntry {
	utxo := &TransactionOutput{
		OutputHash:  &utxoKey.TxID,
		OutputIndex: utxoKey.Index,
		Spent:       false,
	}

	err := postgres.db.Model(utxo).WherePK().Select()
	if err != nil {
		return nil
	}

	return &UtxoEntry{
		PublicKey:   utxo.PublicKey,
		AmountNanos: utxo.AmountNanos,
		// TODO: Block height?
		UtxoType: utxo.OutputType,
		isSpent:  utxo.Spent,
		UtxoKey:  utxoKey,
	}
}

func (postgres *Postgres) GetUtxoEntriesForPublicKey(publicKey []byte) []*UtxoEntry {
	var transactionOutputs []*TransactionOutput
	err := postgres.db.Model(&transactionOutputs).Where("public_key = ?", publicKey).Select()
	if err != nil {
		return nil
	}

	var utxoEntries []*UtxoEntry
	for _, utxo := range transactionOutputs {
		utxoEntries = append(utxoEntries, &UtxoEntry{
			PublicKey:   utxo.PublicKey,
			AmountNanos: utxo.AmountNanos,
			// TODO: Block height?
			UtxoType: utxo.OutputType,
			isSpent:  utxo.Spent,
			UtxoKey: &UtxoKey{
				TxID:  *utxo.OutputHash,
				Index: utxo.OutputIndex,
			},
		})

	}

	return utxoEntries
}

//
// BlockView Flushing
//

func (postgres *Postgres) FlushView(view *UtxoView) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		if err := postgres.flushUtxos(tx, view); err != nil {
			return err
		}
		if err := postgres.flushProfiles(tx, view); err != nil {
			return err
		}
		if err := postgres.flushPosts(tx, view); err != nil {
			return err
		}
		if err := postgres.flushLikes(tx, view); err != nil {
			return err
		}
		if err := postgres.flushFollows(tx, view); err != nil {
			return err
		}
		if err := postgres.flushDiamonds(tx, view); err != nil {
			return err
		}
		if err := postgres.flushMessages(tx, view); err != nil {
			return err
		}
		if err := postgres.flushCreatorCoinBalances(tx, view); err != nil {
			return err
		}

		return nil
	})
}

func (postgres *Postgres) flushUtxos(tx *pg.Tx, view *UtxoView) error {
	var outputs []*TransactionOutput
	for utxoKeyIter, utxoEntry := range view.UtxoKeyToUtxoEntry {
		// Making a copy of the iterator is required
		utxoKey := utxoKeyIter
		outputs = append(outputs, &TransactionOutput{
			OutputHash:  &utxoKey.TxID,
			OutputIndex: utxoKey.Index,
			OutputType:  utxoEntry.UtxoType,
			PublicKey:   utxoEntry.PublicKey,
			AmountNanos: utxoEntry.AmountNanos,
			Spent:       utxoEntry.isSpent,
		})
	}

	_, err := tx.Model(&outputs).WherePK().OnConflict("(output_hash, output_index) DO UPDATE").Insert()
	if err != nil {
		return err
	}

	return nil
}

func (postgres *Postgres) flushProfiles(tx *pg.Tx, view *UtxoView) error {
	var insertProfiles []*Profile
	var deleteProfiles []*Profile
	for pkidIter, profileEntry := range view.ProfilePKIDToProfileEntry {
		// We don't have to do actually delete these profile entries. The DO UPDATE clause takes care of these changes.
		if profileEntry.isDeleted {
			glog.Infof("DELETED PROFILE %v %v", profileEntry.PublicKey, profileEntry.Username)
			continue
		}

		// Making a copy of the iterator is required
		pkid := pkidIter
		profile := &Profile{
			PKID:                    &pkid,
			PublicKey:               NewPublicKey(profileEntry.PublicKey),
			Username:                string(profileEntry.Username),
			Description:             string(profileEntry.Description),
			ProfilePic:              profileEntry.ProfilePic,
			CreatorBasisPoints:      profileEntry.CreatorBasisPoints,
			BitCloutLockedNanos:     profileEntry.BitCloutLockedNanos,
			NumberOfHolders:         profileEntry.NumberOfHolders,
			CoinsInCirculationNanos: profileEntry.CoinsInCirculationNanos,
			CoinWatermarkNanos:      profileEntry.CoinWatermarkNanos,
		}

		if profileEntry.isDeleted {
			deleteProfiles = append(deleteProfiles, profile)
		} else {
			insertProfiles = append(insertProfiles, profile)
		}
	}

	if len(insertProfiles) > 0 {
		_, err := tx.Model(&insertProfiles).WherePK().OnConflict("(pkid) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if len(deleteProfiles) > 0 {
		_, err := tx.Model(&deleteProfiles).Returning("NULL").Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushPosts(tx *pg.Tx, view *UtxoView) error {
	var insertPosts []*Post
	var deletePosts []*Post
	for _, postEntry := range view.PostHashToPostEntry {
		post := &Post{
			PostHash:          postEntry.PostHash,
			PosterPublicKey:   postEntry.PosterPublicKey,
			Body:              string(postEntry.Body),
			RecloutedPostHash: postEntry.RecloutedPostHash,
			QuotedReclout:     postEntry.IsQuotedReclout,
			Timestamp:         postEntry.TimestampNanos,
			Hidden:            postEntry.IsHidden,
			LikeCount:         postEntry.LikeCount,
			RecloutCount:      postEntry.RecloutCount,
			QuoteRecloutCount: postEntry.QuoteRecloutCount,
			DiamondCount:      postEntry.DiamondCount,
			CommentCount:      postEntry.CommentCount,
			Pinned:            postEntry.IsPinned,
			ExtraData:         postEntry.PostExtraData,
		}

		if len(postEntry.ParentStakeID) > 0 {
			post.ParentPostHash = NewBlockHash(postEntry.ParentStakeID)
		}

		if postEntry.isDeleted {
			deletePosts = append(deletePosts, post)
		} else {
			insertPosts = append(insertPosts, post)
		}
	}

	if len(insertPosts) > 0 {
		_, err := tx.Model(&insertPosts).WherePK().OnConflict("(post_hash) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if len(deletePosts) > 0 {
		_, err := tx.Model(&deletePosts).Returning("NULL").Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushLikes(tx *pg.Tx, view *UtxoView) error {
	var insertLikes []*Like
	var deleteLikes []*Like
	for _, likeEntry := range view.LikeKeyToLikeEntry {
		like := &Like{
			LikerPublicKey: likeEntry.LikerPubKey,
			LikedPostHash:  likeEntry.LikedPostHash,
		}

		if likeEntry.isDeleted {
			deleteLikes = append(deleteLikes, like)
		} else {
			insertLikes = append(insertLikes, like)
		}
	}

	if len(insertLikes) > 0 {
		_, err := tx.Model(&insertLikes).WherePK().OnConflict("DO NOTHING").Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if len(deleteLikes) > 0 {
		_, err := tx.Model(&deleteLikes).Returning("NULL").Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushFollows(tx *pg.Tx, view *UtxoView) error {
	var insertFollows []*Follow
	var deleteFollows []*Follow
	for _, followEntry := range view.FollowKeyToFollowEntry {
		follow := &Follow{
			FollowerPKID: followEntry.FollowerPKID,
			FollowedPKID: followEntry.FollowedPKID,
		}

		if followEntry.isDeleted {
			deleteFollows = append(deleteFollows, follow)
		} else {
			insertFollows = append(insertFollows, follow)
		}
	}

	if len(insertFollows) > 0 {
		_, err := tx.Model(&insertFollows).WherePK().OnConflict("DO NOTHING").Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if len(deleteFollows) > 0 {
		_, err := tx.Model(&deleteFollows).Returning("NULL").Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushDiamonds(tx *pg.Tx, view *UtxoView) error {
	var insertDiamonds []*Diamond
	var deleteDiamonds []*Diamond
	for _, diamondEntry := range view.DiamondKeyToDiamondEntry {
		diamond := &Diamond{
			SenderPKID:      diamondEntry.SenderPKID,
			ReceiverPKID:    diamondEntry.ReceiverPKID,
			DiamondPostHash: diamondEntry.DiamondPostHash,
			DiamondLevel:    uint8(diamondEntry.DiamondLevel),
		}

		if diamondEntry.isDeleted {
			deleteDiamonds = append(deleteDiamonds, diamond)
		} else {
			insertDiamonds = append(insertDiamonds, diamond)
		}
	}

	if len(insertDiamonds) > 0 {
		_, err := tx.Model(&insertDiamonds).WherePK().OnConflict("(sender_pkid, receiver_pkid, diamond_post_hash) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if len(deleteDiamonds) > 0 {
		_, err := tx.Model(&deleteDiamonds).Returning("NULL").Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushMessages(tx *pg.Tx, view *UtxoView) error {
	var insertMessages []*Message
	var deleteMessages []*Message
	for _, message := range view.MessageMap {
		if message.isDeleted {
			deleteMessages = append(deleteMessages, message)
		} else {
			insertMessages = append(insertMessages, message)
		}
	}

	if len(insertMessages) > 0 {
		// TODO: There should never be a conflict here. Should we raise an error?
		_, err := tx.Model(&insertMessages).WherePK().OnConflict("(message_hash) DO NOTHING").Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if len(deleteMessages) > 0 {
		_, err := tx.Model(&deleteMessages).Returning("NULL").Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) flushCreatorCoinBalances(tx *pg.Tx, view *UtxoView) error {
	var insertBalances []*CreatorCoinBalance
	var deleteBalances []*CreatorCoinBalance
	for _, balanceEntry := range view.HODLerPKIDCreatorPKIDToBalanceEntry {
		balance := &CreatorCoinBalance{
			HolderPKID:   balanceEntry.HODLerPKID,
			CreatorPKID:  balanceEntry.CreatorPKID,
			BalanceNanos: balanceEntry.BalanceNanos,
			HasPurchased: balanceEntry.HasPurchased,
		}

		if balanceEntry.isDeleted {
			deleteBalances = append(deleteBalances, balance)
		} else {
			insertBalances = append(insertBalances, balance)
		}
	}

	if len(insertBalances) > 0 {
		_, err := tx.Model(&insertBalances).WherePK().OnConflict("(holder_pkid, creator_pkid) DO UPDATE").Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if len(deleteBalances) > 0 {
		_, err := tx.Model(&deleteBalances).Returning("NULL").Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

//
// Profiles
//

func (postgres *Postgres) GetProfileForUsername(nonLowercaseUsername string) *Profile {
	var profile Profile
	err := postgres.db.Model(&profile).Where("username = ?", nonLowercaseUsername).First()
	if err != nil {
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfileForPublicKey(publicKey []byte) *Profile {
	var profile Profile
	err := postgres.db.Model(&profile).Where("public_key = ?", publicKey).First()
	if err != nil {
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfile(pkid PKID) *Profile {
	var profile Profile
	err := postgres.db.Model(&profile).Where("pkid = ?", pkid).First()
	if err != nil {
		return nil
	}
	return &profile
}

func (postgres *Postgres) GetProfilesForPublicKeys(publicKeys []*PublicKey) []*Profile {
	var profiles []*Profile
	err := postgres.db.Model(&profiles).WhereIn("public_key IN (?)", publicKeys).Select()
	if err != nil {
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesByCoinValue(startLockedNanos uint64, limit int) []*Profile {
	var profiles []*Profile
	err := postgres.db.Model(&profiles).Where("bit_clout_locked_nanos < ?", startLockedNanos).
		OrderExpr("bit_clout_locked_nanos DESC").Limit(limit).Select()
	if err != nil {
		return nil
	}
	return profiles
}

func (postgres *Postgres) GetProfilesForUsernamePrefixByCoinValue(usernamePrefix string, limit int) []*Profile {
	var profiles []*Profile
	err := postgres.db.Model(&profiles).Where("username ILIKE ?", fmt.Sprintf("%s%%", usernamePrefix)).
		Where("bit_clout_locked_nanos >= 0").OrderExpr("bit_clout_locked_nanos DESC").Limit(limit).Select()
	if err != nil {
		return nil
	}
	return profiles
}

//
// Posts
//

func (postgres *Postgres) GetPost(postHash *BlockHash) *Post {
	var post Post
	err := postgres.db.Model(&post).Where("post_hash = ?", postHash).First()
	if err != nil {
		return nil
	}
	return &post
}

func (postgres *Postgres) GetPosts(publicKey []byte, startTime uint64, limit uint64) []*Post {
	var posts []*Post
	err := postgres.db.Model(&posts).
		Where("poster_public_key = ?", publicKey).Where("timestamp < ?", startTime).
		Where("hidden IS NULL").Where("parent_post_hash IS NULL").
		OrderExpr("timestamp DESC").Limit(int(limit)).Select()
	if err != nil {
		return nil
	}
	return posts
}

//
// Comments
//

// TODO: Pagination
func (postgres *Postgres) GetComments(parentPostHash *BlockHash) []*Post {
	var posts []*Post
	err := postgres.db.Model(&posts).Where("parent_post_hash = ?", parentPostHash).Select()
	if err != nil {
		return nil
	}
	return posts
}

func (postgres *Postgres) GetMessage(messageHash *BlockHash) *Message {
	var message Message
	err := postgres.db.Model(&message).Where("message_hash = ?", messageHash).First()
	if err != nil {
		return nil
	}
	return &message
}

func (postgres *Postgres) GetLike(likerPublicKey []byte, likedPostHash *BlockHash) *Like {
	like := Like{
		LikerPublicKey: likerPublicKey,
		LikedPostHash:  likedPostHash,
	}
	err := postgres.db.Model(&like).WherePK().First()
	if err != nil {
		return nil
	}
	return &like
}

func (postgres *Postgres) GetLikes(postHash *BlockHash) []*Like {
	var likes []*Like
	err := postgres.db.Model(&likes).Where("liked_post_hash = ?", postHash).Select()
	if err != nil {
		return nil
	}
	return likes
}

//
// Follows
//

func (postgres *Postgres) GetFollow(followerPkid *PKID, followedPkid *PKID) *Follow {
	follow := Follow{
		FollowerPKID: followerPkid,
		FollowedPKID: followedPkid,
	}
	err := postgres.db.Model(&follow).WherePK().First()
	if err != nil {
		return nil
	}
	return &follow
}

func (postgres *Postgres) GetFollows(follows []*Follow) []*Follow {
	err := postgres.db.Model(&follows).WherePK().Select()
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetFollowing(pkid *PKID) []*Follow {
	var follows []*Follow
	err := postgres.db.Model(&follows).Where("follower_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetFollowers(pkid *PKID) []*Follow {
	var follows []*Follow
	err := postgres.db.Model(&follows).Where("followed_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return follows
}

func (postgres *Postgres) GetDiamond(senderPkid *PKID, receiverPkid *PKID, postHash *BlockHash) *Diamond {
	diamond := Diamond{
		SenderPKID:      senderPkid,
		ReceiverPKID:    receiverPkid,
		DiamondPostHash: postHash,
	}
	err := postgres.db.Model(&diamond).WherePK().First()
	if err != nil {
		return nil
	}
	return &diamond
}

//
// Creator Coins
//

func (postgres *Postgres) GetCreatorCoinBalance(holderPkid *PKID, creatorPkid *PKID) *CreatorCoinBalance {
	balance := CreatorCoinBalance{
		HolderPKID:  holderPkid,
		CreatorPKID: creatorPkid,
	}
	err := postgres.db.Model(&balance).WherePK().First()
	if err != nil {
		return nil
	}
	return &balance
}

func (postgres *Postgres) GetHoldings(pkid *PKID) []*CreatorCoinBalance {
	var holdings []*CreatorCoinBalance
	err := postgres.db.Model(&holdings).Where("holder_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return holdings
}

func (postgres *Postgres) GetHolders(pkid *PKID) []*CreatorCoinBalance {
	var holdings []*CreatorCoinBalance
	err := postgres.db.Model(&holdings).Where("creator_pkid = ?", pkid).Select()
	if err != nil {
		return nil
	}
	return holdings
}

//
// Chain Init
//

func (postgres *Postgres) InitGenesisBlock(params *BitCloutParams, db *badger.DB) error {
	// Construct a node for the genesis block. Its height is zero and it has no parents. Its difficulty should be
	// set to the initial difficulty specified in the parameters and it should be assumed to be
	// valid and stored by the end of this function.
	genesisBlock := params.GenesisBlock
	diffTarget := MustDecodeHexBlockHash(params.MinDifficultyTargetHex)
	blockHash := MustDecodeHexBlockHash(params.GenesisBlockHashHex)
	genesisNode := NewBlockNode(
		nil,
		blockHash,
		0,
		diffTarget,
		BytesToBigint(ExpectedWorkForBlockHash(diffTarget)[:]),
		genesisBlock.Header,
		StatusHeaderValidated|StatusBlockProcessed|StatusBlockStored|StatusBlockValidated,
	)

	// Create the chain
	err := postgres.UpsertChain("main", blockHash)
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error upserting chain: %v", err)
	}

	// Set the fields in the db to reflect the current state of our chain.
	//
	// Set the best hash to the genesis block in the db since its the only node
	// we're currently aware of. Set it for both the header chain and the block
	// chain.
	err = postgres.UpsertBlock(genesisNode)
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error upserting block: %v", err)
	}

	for index, txOutput := range params.SeedBalances {
		_, err := postgres.db.Model(&TransactionOutput{
			OutputHash:  &BlockHash{},
			OutputIndex: uint32(index),
			OutputType:  UtxoTypeOutput,
			AmountNanos: txOutput.AmountNanos,
			PublicKey:   txOutput.PublicKey,
		}).Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	return nil
}

//
// API
//

func (postgres *Postgres) GetNotifications(publicKey string) ([]*Notification, error) {
	keyBytes, _, _ := Base58CheckDecode(publicKey)

	var notifications []*Notification
	err := postgres.db.Model(&notifications).Where("to_user = ?", keyBytes).Order("timestamp desc").Limit(100).Select()
	if err != nil {
		return nil, err
	}

	return notifications, nil
}
