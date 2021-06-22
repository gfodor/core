package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {
		_, err := db.Exec(`
			CREATE TABLE chains (
                name     TEXT  NOT NULL PRIMARY KEY,
				tip_hash BYTEA NOT NULL
			)
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE blocks (
				hash              BYTEA PRIMARY KEY,
				parent_hash       BYTEA,
				height            BIGINT NOT NULL,
				difficulty_target BYTEA  NOT NULL,
				cum_work          BYTEA  NOT NULL,
				status            TEXT   NOT NULL,
				tx_merkle_root    BYTEA  NOT NULL,
				timestamp         BIGINT NOT NULL,
				nonce             BIGINT NOT NULL,
				extra_nonce       BIGINT,
				version           INT,
				notified          BOOL NOT NULL
			)
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE transactions (
				hash       BYTEA PRIMARY KEY,
				block_hash BYTEA NOT NULL,
				type       SMALLINT NOT NULL,
				public_key BYTEA,
				extra_data JSONB,
				r          BYTEA,
				s          BYTEA
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE transaction_outputs (
				output_hash  BYTEA    NOT NULL,
				output_index INT      NOT NULL,
				output_type  SMALLINT NOT NULL,
				public_key   BYTEA    NOT NULL,
				amount_nanos BIGINT   NOT NULL,
				spent        BOOL     NOT NULL,
				input_hash   BYTEA,
				input_index  INT,

				PRIMARY KEY (output_hash, output_index)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_block_rewards (
				transaction_hash BYTEA PRIMARY KEY,
				extra_data       BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_bitcoin_exchanges (
				transaction_hash    BYTEA PRIMARY KEY,
				bitcoin_block_hash  BYTEA NOT NULL,
				bitcoin_merkle_root BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_private_messages (
				transaction_hash     BYTEA PRIMARY KEY,
				recipient_public_key BYTEA  NOT NULL,
				encrypted_text       BYTEA  NOT NULL,
				timestamp_nanos      BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_submit_posts (
				transaction_hash    BYTEA PRIMARY KEY,
				post_hash_to_modify BYTEA  NOT NULL,
				parent_stake_id     BYTEA  NOT NULL,
				body                BYTEA  NOT NULL,
				timestamp_nanos     BIGINT NOT NULL,
				is_hidden           BOOL   NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_update_exchange_rates (
				transaction_hash      BYTEA PRIMARY KEY,
				usd_cents_per_bitcoin BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_update_profiles (
				transaction_hash         BYTEA PRIMARY KEY,
				profile_public_key       BYTEA,
				new_username             BYTEA,
				new_description          BYTEA,
				new_profile_pic          BYTEA,
				new_creator_basis_points BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_follows (
				transaction_hash    BYTEA PRIMARY KEY,
				followed_public_key BYTEA NOT NULL,
				is_unfollow         BOOL NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_likes (
				transaction_hash BYTEA PRIMARY KEY,
				liked_post_hash  BYTEA NOT NULL,
				is_unlike        BOOL NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_creator_coins (
				transaction_hash                BYTEA PRIMARY KEY,
				profile_public_key              BYTEA NOT NULL,
				operation_type                  SMALLINT NOT NULL,
				bit_clout_to_sell_nanos         BIGINT NOT NULL,
				creator_coin_to_sell_nanos      BIGINT NOT NULL,
				bit_clout_to_add_nanos          BIGINT NOT NULL,
				min_bit_clout_expected_nanos    BIGINT NOT NULL,
				min_creator_coin_expected_nanos BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_creator_coin_transfers (
				transaction_hash               BYTEA PRIMARY KEY,
				profile_public_key             BYTEA NOT NULL,
				creator_coin_to_transfer_nanos BIGINT NOT NULL,
				receiver_public_key            BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE metadata_swap_identities (
				transaction_hash BYTEA PRIMARY KEY,
				from_public_key  BYTEA NOT NULL,
				to_public_key    BYTEA NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE notifications (
				transaction_hash BYTEA PRIMARY KEY,
				mined            BOOL NOT NULL,
				to_user          BYTEA NOT NULL,
				from_user        BYTEA NOT NULL,
				other_user       BYTEA,
				type             SMALLINT NOT NULL,
				amount           BIGINT,
				post_hash        BYTEA,
				timestamp        BIGINT NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE profiles (
				pkid                       BYTEA PRIMARY KEY,
				public_key                 BYTEA NOT NULL,
                username                   TEXT,
				description                TEXT,
				profile_pic                BYTEA,
				creator_basis_points       BIGINT,
				bit_clout_locked_nanos     BIGINT,
				number_of_holders          BIGINT,
				coins_in_circulation_nanos BIGINT,
				coin_watermark_nanos       BIGINT
			);

			CREATE INDEX profiles_public_key ON profiles(public_key);
			CREATE INDEX profiles_username ON profiles(username);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE posts (
				post_hash           BYTEA PRIMARY KEY,
				poster_public_key   BYTEA NOT NULL,
				parent_post_hash    BYTEA,
                body                TEXT,
				reclouted_post_hash BYTEA,
				quoted_reclout      BOOL,
				timestamp           BIGINT,
				hidden              BOOL,
				like_count          BIGINT,
				reclout_count       BIGINT,
				quote_reclout_count BIGINT,
				diamond_count       BIGINT,
				comment_count       BIGINT,
				pinned              BOOL,
				extra_data          JSONB
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE likes (
				liker_public_key BYTEA,
				liked_post_hash  BYTEA,

				PRIMARY KEY (liker_public_key, liked_post_hash)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE follows (
				follower_pkid BYTEA,
				followed_pkid BYTEA,

				PRIMARY KEY (follower_pkid, followed_pkid)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE diamonds (
				sender_pkid       BYTEA,
				receiver_pkid     BYTEA,
				diamond_post_hash BYTEA,
				diamond_level     SMALLINT,

				PRIMARY KEY (sender_pkid, receiver_pkid, diamond_post_hash)
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE messages (
				message_hash         BYTEA PRIMARY KEY,
				sender_public_key    BYTEA,
				recipient_public_key BYTEA,
				encrypted_text       BYTEA,
				timestamp_nanos      BIGINT
			);
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE creator_coin_balances (
				holder_pkid   BYTEA,
				creator_pkid  BYTEA,
				balance_nanos BIGINT,
				has_purchased BOOL,

				PRIMARY KEY (holder_pkid, creator_pkid)
			);
		`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			DROP TABLE chains;
			DROP TABLE blocks;
			DROP TABLE transactions;
			DROP TABLE transaction_outputs;
			DROP TABLE metadata_block_rewards;
			DROP TABLE metadata_bitcoin_exchanges;
			DROP TABLE metadata_private_messages;
			DROP TABLE metadata_submit_posts;
			DROP TABLE metadata_update_exchange_rates;
			DROP TABLE metadata_update_profiles;
			DROP TABLE metadata_follows;
			DROP TABLE metadata_likes;
			DROP TABLE metadata_creator_coins;
			DROP TABLE metadata_creator_coin_transfers;
			DROP TABLE metadata_swap_identities;
			DROP TABLE notifications;
			DROP TABLE profiles;
			DROP TABLE posts;
			DROP TABLE likes;
			DROP TABLE follows;
			DROP TABLE diamonds;
			DROP TABLE messages;
			DROP TABLE creator_coin_balances;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20210623152412_create_tables", up, down, opts)
}
