package repo

type Resolvers map[string]Provider

type Provider struct {
	Account      Account       `json:"Account"`
	Certificates []Certificate `json:"Certificates"`
}

type Account struct {
	Email        string       `json:"Email"`
	Registration Registration `json:"Registration"`
	PrivateKey   string       `json:"PrivateKey"`
	KeyType      string       `json:"KeyType"`
}

type Registration struct {
	Body RegistrationBody `json:"body"`
	URI  string           `json:"uri"`
}

type RegistrationBody struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact"`
}

type Certificate struct {
	Domain struct {
		Main string   `json:"main"`
		Sans []string `json:"sans"`
	} `json:"domain"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Store       string `json:"Store"`
}

/*

type Provider struct {
	Account struct {
		Email        string `json:"Email"`
		Registration struct {
			Body struct {
				Status  string   `json:"status"`
				Contact []string `json:"contact"`
			} `json:"body"`
			URI string `json:"uri"`
		} `json:"Registration"`
		PrivateKey string `json:"PrivateKey"`
		KeyType    string `json:"KeyType"`
	} `json:"Account"`
	Certificates []struct {
		Domain struct {
			Main string   `json:"main"`
			Sans []string `json:"sans"`
		} `json:"domain"`
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
		Store       string `json:"Store"`
	} `json:"Certificates"`
}

*/
