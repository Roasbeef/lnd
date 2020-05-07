package lncfg

import (
	"fmt"

	"github.com/lightningnetwork/lnd/channeldb/kvdb"
	"github.com/lightningnetwork/lnd/channeldb/kvdb/etcd"
)

const (
	dbName      = "channel.db"
	boltBackend = "bolt"
	etcdBackend = "etcd"
)

// BoltDB holds bolt configuration.
type BoltDB struct {
	NoFreeListSync bool `long:"nofreelistsync" description:"If true, prevents the database from syncing its freelist to disk"`
}

// EtcdDB hold etcd configuration.
type EtcdDB struct {
	Host string `long:"host" description:"Etcd database host."`

	User string `long:"user" description:"Etcd database user."`

	Pass string `long:"pass" description:"Password for the database user."`

	CollectStats bool `long:"collect_stats" description:"Wheter to collect etcd commit stats."`

	TLSPath string
}

// DB holds database configuration for LND.
type DB struct {
	Backend string `long:"backend" description:"The selected database backend."`

	Etcd *EtcdDB `group:"etcd" namespace:"etcd" description:"Etcd settings."`

	Bolt *BoltDB `group:"bolt" namespace:"bolt" description:"Bolt settings."`
}

// NewDB creates and returns a new default DB config.
func DefaultDB() *DB {
	return &DB{
		Backend: boltBackend,
		Bolt: &BoltDB{
			NoFreeListSync: true,
		},
	}
}

// Validate validates the DB config.
func (db *DB) Validate() error {
	switch db.Backend {
	case boltBackend:

	case etcdBackend:
		if db.Etcd.Host == "" {
			return fmt.Errorf("host must be set")
		}

	default:
		return fmt.Errorf("unknwon backend, must be either \"%v\" or \"%v\"",
			boltBackend, etcdBackend)
	}

	return nil
}

// GetBackend returns a kvdb.Backend as set in the DB config. The database
// returned is the local database, and the second the remote database. The
// remote database will ALWAYS be non-nil, while the remote database will only
// be populated if etcd is specified.
func (db *DB) GetBackend(path string) (kvdb.Backend, kvdb.Backend, error) {
	var (
		localDB, remoteDB kvdb.Backend
		err               error
	)

	if db.Backend == etcdBackend {
		backendConfig := etcd.BackendConfig{
			Host:               db.Etcd.Host,
			User:               db.Etcd.User,
			Pass:               db.Etcd.Pass,
			CollectCommitStats: db.Etcd.CollectStats,
			TLSPath:            db.Etcd.TLSPath,
		}
		fmt.Println("DOING ETCD!!!!!!")

		remoteDB, err = kvdb.Open(kvdb.EtcdBackendName, backendConfig)
		if err != nil {
			return nil, nil, err
		}
	}

	localDB, err = kvdb.GetBoltBackend(
		path, dbName, db.Bolt.NoFreeListSync,
	)
	if err != nil {
		return nil, nil, err
	}

	return localDB, remoteDB, nil
}

// Compile-time constraint to ensure Workers implements the Validator interface.
var _ Validator = (*DB)(nil)
