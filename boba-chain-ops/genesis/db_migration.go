package genesis

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/log/v3"
)

func MigrateDB(dbPath string, allocPath string, genesisConfigPath string) error {
	// load alloc file
	file, err := os.Open(allocPath)
	if err != nil {
		log.Error("failed to open alloc file", "err", err)
		return err
	}
	defer file.Close()

	bytes, _ := ioutil.ReadAll(file)
	genesisAccount, err := MigrateAlloc(bytes)
	if err != nil {
		log.Error("failed to migrate alloc", "err", err)
		return err
	}

	// load genesis config
	genesisCfgFile, err := os.Open(genesisConfigPath)
	if err != nil {
		log.Error("failed to open genesis config file", "err", err)
		return err
	}
	defer genesisCfgFile.Close()

	genesis := new(types.Genesis)
	if err := json.NewDecoder(genesisCfgFile).Decode(genesis); err != nil {
		log.Error("failed to decode genesis config file", "err", err)
		return err
	}
	genesis.Alloc = genesisAccount

	return nil
}
