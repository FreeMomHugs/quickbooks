package models

type QuickbooksConnectionInfo struct {
	TokenEndpoint         string
	JWKSURI               string
	AuthorizationEndpoint string
	RealmID               string
	AccessToken           string
	RefreshToken          string
	RevocationEndpoint    string
	UserInfoEndpoint      string
	Issuer                string
}

type AccountsQueryResults struct {
	QueryResponse struct {
		Account []struct {
			Name                          string  `json:"Name"`
			SubAccount                    bool    `json:"SubAccount"`
			FullyQualifiedName            string  `json:"FullyQualifiedName"`
			Active                        bool    `json:"Active"`
			Classification                string  `json:"Classification"`
			AccountType                   string  `json:"AccountType"`
			AccountSubType                string  `json:"AccountSubType"`
			CurrentBalance                float64 `json:"CurrentBalance"`
			CurrentBalanceWithSubAccounts float64 `json:"CurrentBalanceWithSubAccounts"`
			CurrencyRef                   struct {
				Value string `json:"value"`
				Name  string `json:"name"`
			} `json:"CurrencyRef"`
			Domain    string `json:"domain"`
			Sparse    bool   `json:"sparse"`
			ID        string `json:"Id"`
			SyncToken string `json:"SyncToken"`
			MetaData  struct {
				CreateTime      string `json:"CreateTime"`
				LastUpdatedTime string `json:"LastUpdatedTime"`
			} `json:"MetaData"`
			ParentRef struct {
				Value string `json:"value"`
			} `json:"ParentRef,omitempty"`
		} `json:"Account"`
		StartPosition int `json:"startPosition"`
		MaxResults    int `json:"maxResults"`
	} `json:"QueryResponse"`
	Time string `json:"time"`
}

type QBAccount struct {
	Name                          string  `json:"Name"`
	SubAccount                    bool    `json:"SubAccount"`
	FullyQualifiedName            string  `json:"FullyQualifiedName"`
	Active                        bool    `json:"Active"`
	Classification                string  `json:"Classification"`
	AccountType                   string  `json:"AccountType"`
	AccountSubType                string  `json:"AccountSubType"`
	CurrentBalance                float64 `json:"CurrentBalance"`
	CurrentBalanceWithSubAccounts float64 `json:"CurrentBalanceWithSubAccounts"`
	CurrencyRef                   struct {
		Value string `json:"value"`
		Name  string `json:"name"`
	} `json:"CurrencyRef"`
	Domain    string `json:"domain"`
	Sparse    bool   `json:"sparse"`
	ID        string `json:"Id"`
	SyncToken string `json:"SyncToken"`
	MetaData  struct {
		CreateTime      string `json:"CreateTime"`
		LastUpdatedTime string `json:"LastUpdatedTime"`
	} `json:"MetaData"`
	ParentRef struct {
		Value string `json:"value"`
	} `json:"ParentRef,omitempty"`
}
