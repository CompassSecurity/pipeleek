package shodan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/perimeterx/marshmallow"
	"github.com/rs/zerolog/log"
	"github.com/wandb/parallel"
)

type shodan struct {
	Module string `json:"module"`
}

type result struct {
	Hostnames []string `json:"hostnames"`
	Port      int      `json:"port"`
	IPString  string   `json:"ip_str"`
	Shodan    shodan   `json:"_shodan"`
}

// RunShodan performs the Shodan scan
func RunShodan(shodanJson string) {

	// #nosec G304 - User-provided file path via CLI flag, user controls their own filesystem
	jsonFile, err := os.Open(shodanJson)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("failed opening file")
	}
	defer func() { _ = jsonFile.Close() }()

	data, _ := io.ReadAll(jsonFile)
	ctx := context.Background()
	group := parallel.Limited(ctx, 4)
	ctr := 0

	for _, line := range bytes.Split(data, []byte{'\n'}) {
		ctr = ctr + 1
		d := result{}
		_, err := marshmallow.Unmarshal(line, &d)
		if err != nil {
			log.Error().Stack().Err(err).Msg("failed unmarshalling jsonl line")
		} else {

			isHttps := false
			if strings.EqualFold("https", d.Shodan.Module) {
				isHttps = true
			}

			if len(d.Hostnames) == 0 {
				group.Go(func(ctx context.Context) {
					testHost(d.IPString, d.Port, isHttps)
				})
			} else {
				for _, hostname := range d.Hostnames {
					group.Go(func(ctx context.Context) {
						testHost(hostname, d.Port, isHttps)
					})
				}
			}
		}

	}

	group.Wait()
	log.Info().Int("nr", ctr).Msg("Tested number of Gitlab instances")
	log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
}

func testHost(hostname string, port int, https bool) {
	var url string
	if https {
		url = "https://" + hostname + ":" + strconv.Itoa(port)
	} else {
		url = "http://" + hostname + ":" + strconv.Itoa(port)
	}
	registration, err := isRegistrationEnabled(url)
	if err != nil {
		log.Error().Stack().Err(err).Msg("regisration check failed")
	}
	nrOfProjects, err := checkNrPublicRepos(url)
	if err != nil {
		log.Error().Stack().Err(err).Msg("check nr public repos failed")
	}
	log.Info().Bool("registration", registration).Int("nrProjects", nrOfProjects).Str("url", url+"/explore").Msg("")
}

func isRegistrationEnabled(base string) (bool, error) {
	u, err := url.Parse(base)
	if err != nil {
		return false, err
	}

	u.Path = path.Join(u.Path, "/users/somenotexistigusr/exists")
	s := u.String()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	res, err := client.R().Get(s)

	if err != nil {
		return false, err
	}

	if res.StatusCode() == 200 {
		resData := res.Bytes()

		// sanity check to avoid false positives
		if strings.Contains(string(resData), "{\"exists\":false}") {
			return true, nil
		}

		log.Debug().Msg("Missed sanity check")
		return false, err
	} else {
		log.Debug().Int("http", res.StatusCode()).Msg("Registration username test request")
		return false, nil
	}
}

func checkNrPublicRepos(base string) (int, error) {
	u, err := url.Parse(base)
	if err != nil {
		return 0, err
	}

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	u.Path = "/api/v4/projects"
	s := u.String()
	res, err := client.R().Get(s + "?per_page=100")
	if err != nil {
		return 0, err
	}

	if res.StatusCode() == 200 {
		resData := res.Bytes()
		var val []map[string]interface{}
		if err := json.Unmarshal(resData, &val); err != nil {
			return 0, err
		}
		return len(val), nil
	}

	return 0, err
}
