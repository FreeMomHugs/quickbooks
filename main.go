package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	internal "github.com/FreeMomHugs/myFMHInternal"
	"github.com/FreeMomHugs/quickbooks/cache"
	"github.com/FreeMomHugs/quickbooks/models"
	qbdatastore "github.com/FreeMomHugs/quickbooks/qbdatastore"
	"github.com/google/uuid"
	"google.golang.org/appengine/v2"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type BearerTokenResponse struct {
	RefreshToken           string `json:"refresh_token"`
	AccessToken            string `json:"access_token"`
	TokenType              string `json:"token_type"`
	IdToken                string `json:"id_token"`
	ExpiresIn              int64  `json:"expires_in"`
	XRefreshTokenExpiresIn int64  `json:"x_refresh_token_expires_in"`
}

func main() {
	//http.HandleFunc("/getCompanyInfo/", GetCompanyInfo)
	//http.HandleFunc("/getAccounts/", GetAccounts)
	//http.HandleFunc("/discovery/", Discovery)
	//http.HandleFunc("/refreshToken/", RefreshToken)
	//http.HandleFunc("/connectToQuickbooks/", ConnectToQuickbooks)
	//http.HandleFunc("/oauth2redirect/", CallBackFromOAuth)
	http.HandleFunc("/update/", UpdateAccounts)
	http.HandleFunc("/webhooktest/", WebhookTest)

	appengine.Main()
}

func WebhookTest(w http.ResponseWriter, r *http.Request) {
	sigHeader := "intuit-signature"
	token := os.Getenv("WEBHOOK_VALIDATION_TOKEN")
	//algo := "HmacSHA256"
	signature := r.Header.Get(sigHeader)
	if signature == "" {
		return
	}
	h := hmac.New(sha256.New, []byte(token))
	data, _ := ioutil.ReadAll(r.Body)
	h.Write([]byte(data))
	result := hex.EncodeToString(h.Sum(nil))
	decodedSig, _ := base64.StdEncoding.DecodeString(signature)
	signature = hex.EncodeToString(decodedSig)
	if result != signature {
		log.Println("Could not validate sig, recieved sig: " + signature + " Calculate sig: " + result)
	} else {
		log.Println("Sig is valid, calculated: " + result + " received sig: " + signature)
	}

}

func UpdateAccounts(w http.ResponseWriter, r *http.Request) {
	sigHeader := "intuit-signature"
	token := os.Getenv("WEBHOOK_VALIDATION_TOKEN")
	//algo := "HmacSHA256"
	signature := r.Header.Get(sigHeader)
	if signature == "" {
		return
	}
	h := hmac.New(sha256.New, []byte(token))
	data, _ := ioutil.ReadAll(r.Body)
	h.Write([]byte(data))
	result := hex.EncodeToString(h.Sum(nil))
	decodedSig, _ := base64.StdEncoding.DecodeString(signature)
	signature = hex.EncodeToString(decodedSig)
	if result != signature {
		log.Println("Could not validate sig, recieved sig: " + signature + " Calculate sig: " + result)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Println("Sig is valid, calculated: " + result + " received sig: " + signature)

	namespace := os.Getenv("NAMESPACE")
	ctx := appengine.NewContext(r)
	ctx, err := appengine.Namespace(ctx, namespace)
	if err != nil {
		log.Println("Unable to swap namespaces to: " + namespace + " Error: " + err.Error())
		panic(err.Error())
	}
	log.Println("Entering Update Accounts ")
	client := &http.Client{}

	connData := qbdatastore.GetQuickbooksConnectionData(ctx)

	//Ideally you would fetch the realmId and the accessToken from the data store based on the user account here.
	realmId := connData.RealmID
	if realmId == "" {
		log.Println("No realm ID.  QBO calls only work if the accounting scope was passed!")
		fmt.Fprintf(w, "No realm ID.  QBO calls only work if the accounting scope was passed!")
	}

	queryString := "select * from Account where Metadata.CreateTime > '2014-12-31'"
	queryString = url.QueryEscape(queryString)
	request, err := http.NewRequest("GET", os.Getenv("INTUIT_ACCOUNTING_API_HOST")+"/v3/company/"+realmId+"/query?query="+queryString+"&minorversion=65", nil)
	if err != nil {
		log.Fatalln(err)
	}
	//set header
	request.Header.Set("accept", "application/json")
	accessToken := connData.AccessToken
	request.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(request)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var accountsQueryResult models.AccountsQueryResults
	json.Unmarshal(body, &accountsQueryResult)
	qbdatastore.UpdateAccountsInfo(ctx, &accountsQueryResult)
}

func Discovery(w http.ResponseWriter, r *http.Request) {
	ctx, _ := appengine.Namespace(appengine.NewContext(r), "quickbooks")
	CallDiscoveryAPI(ctx)
}

/*
 * Sample QBO API call to get CompanyInfo using OAuth2 tokens
 */
func GetCompanyInfo(w http.ResponseWriter, r *http.Request) {
	namespace := "quickbooks"
	ctx := appengine.NewContext(r)
	ctx, err := appengine.Namespace(ctx, namespace)
	if err != nil {
		log.Println("Unable to swap namespaces to: " + namespace + " Error: " + err.Error())
		panic(err.Error())
	}
	log.Println("Entering GetCompanyInfo ")
	client := &http.Client{}

	//Ideally you would fetch the realmId and the accessToken from the data store based on the user account here.
	connData := qbdatastore.GetQuickbooksConnectionData(ctx)
	realmId := connData.RealmID
	if realmId == "" {
		log.Println("No realm ID.  QBO calls only work if the accounting scope was passed!")
		fmt.Fprintf(w, "No realm ID.  QBO calls only work if the accounting scope was passed!")
	}

	request, err := http.NewRequest("GET", os.Getenv("INTUIT_ACCOUNTING_API_HOST")+"/v3/company/"+realmId+"/companyinfo/"+realmId+"?minorversion=8", nil)
	if err != nil {
		log.Fatalln(err)
	}
	//set header
	request.Header.Set("accept", "application/json")
	accessToken := connData.AccessToken
	request.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	responseString := string(body)
	log.Println("Exiting GetCompanyInfo ")
	fmt.Fprintf(w, responseString)

}

/*
 * Sample QBO API call to get CompanyInfo using OAuth2 tokens
 */
func GetAccounts(w http.ResponseWriter, r *http.Request) {
	namespace := os.Getenv("NAMESPACE")
	ctx := appengine.NewContext(r)
	ctx, err := appengine.Namespace(ctx, namespace)
	if err != nil {
		log.Println("Unable to swap namespaces to: " + namespace + " Error: " + err.Error())
		panic(err.Error())
	}
	log.Println("Entering GetCompanyInfo ")
	client := &http.Client{}

	connData := qbdatastore.GetQuickbooksConnectionData(ctx)

	//Ideally you would fetch the realmId and the accessToken from the data store based on the user account here.
	realmId := connData.RealmID
	if realmId == "" {
		log.Println("No realm ID.  QBO calls only work if the accounting scope was passed!")
		fmt.Fprintf(w, "No realm ID.  QBO calls only work if the accounting scope was passed!")
	}

	queryString := "select * from Account where Metadata.CreateTime > '2014-12-31'"
	queryString = url.QueryEscape(queryString)
	request, err := http.NewRequest("GET", os.Getenv("INTUIT_ACCOUNTING_API_HOST")+"/v3/company/"+realmId+"/query?query="+queryString+"&minorversion=65", nil)
	if err != nil {
		log.Fatalln(err)
	}
	//set header
	request.Header.Set("accept", "application/json")
	accessToken := connData.AccessToken
	request.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(request)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var accountsQueryResult models.AccountsQueryResults
	json.Unmarshal(body, &accountsQueryResult)
	qbdatastore.StoreAccountsInfo(ctx, &accountsQueryResult)
	responseString := string(body)
	log.Println("Exiting GetCompanyInfo ")
	fmt.Fprintf(w, responseString)

}

/*
 * Call the refresh endpoint to generate new tokens
 */
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	namespace := "quickbooks"
	ctx := appengine.NewContext(r)
	ctx, err := appengine.Namespace(ctx, namespace)

	log.Println("Entering RefreshToken ")
	client := &http.Client{}
	data := url.Values{}

	//add parameters
	data.Set("grant_type", "refresh_token")
	connData := qbdatastore.GetQuickbooksConnectionData(ctx)

	refreshToken := connData.RefreshToken
	data.Add("refresh_token", refreshToken)

	tokenEndpoint := connData.TokenEndpoint
	request, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		log.Fatalln(err)
	}
	//set the headers
	request.Header.Set("accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	request.Header.Set("Authorization", "Basic "+basicAuth(ctx))

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	bearerTokenResponse, err := getBearerTokenResponse([]byte(body))
	//add the tokens to cache - in real app store in database
	cache.AddToCache(ctx, "access_token", bearerTokenResponse.AccessToken)
	cache.AddToCache(ctx, "refresh_token", bearerTokenResponse.RefreshToken)
	qbci := models.QuickbooksConnectionInfo{
		AccessToken:  bearerTokenResponse.AccessToken,
		RefreshToken: bearerTokenResponse.RefreshToken,
	}
	qbdatastore.UpdateQuickbooksConnectionInfo(ctx, &qbci)
	responseString := string(body)
	log.Println("Exiting RefreshToken ")
	fmt.Fprintf(w, responseString)

}

func getBearerTokenResponse(body []byte) (*BearerTokenResponse, error) {
	var s = new(BearerTokenResponse)
	err := json.Unmarshal(body, &s)
	if err != nil {
		log.Fatalln("error getting BearerTokenResponse:", err)
	}
	return s, err
}

func basicAuth(ctx context.Context) string {
	client_secret := string(internal.AccessSecretVersion(ctx, "qb-client-secret"))
	auth := os.Getenv("CLIENT_ID") + ":" + client_secret
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

/*
 * Handler for connectToQuickbooks button
 */
func ConnectToQuickbooks(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	namespace := "quickbooks"
	ctx, _ = appengine.Namespace(ctx, namespace)
	log.Println("inside connectToQuickbooks ")
	http.Redirect(w, r, PrepareUrl(ctx, os.Getenv("C2QB_SCOPE"), GenerateCSRF(ctx)), http.StatusSeeOther)
}

/*
 * Generates CSRF token
 */
func GenerateCSRF(ctx context.Context) string {
	id := uuid.New()
	csrf := id.String()
	//add to cache since we need this in callback handler to validate the response
	cache.AddToCache(ctx, "csrf", csrf)
	return csrf
}

/*
 * Prepares URL to call the OAuth2 authorization endpoint using Scope, CSRF and redirectURL that is supplied
 */
func PrepareUrl(ctx context.Context, scope string, csrf string) string {
	var Url *url.URL

	connData := qbdatastore.GetQuickbooksConnectionData(ctx)
	authorizationEndpoint := connData.AuthorizationEndpoint
	Url, err := url.Parse(authorizationEndpoint)
	if err != nil {
		panic("error parsing url")
	}

	parameters := url.Values{}
	parameters.Add("client_id", os.Getenv("CLIENT_ID"))
	parameters.Add("response_type", "code")
	parameters.Add("scope", scope)
	parameters.Add("redirect_uri", os.Getenv("REDIRECT_URI"))
	parameters.Add("state", csrf)
	Url.RawQuery = parameters.Encode()

	log.Printf("Encoded URL is %q\n", Url.String())
	return Url.String()

}

/*
 *  This is the redirect handler you configure in your app on developer.intuit.com
 *  The Authorization code has a short lifetime.
 *  Hence unless a user action is quick and mandatory, proceed to exchange the Authorization Code for
 *  BearerToken
 */
func CallBackFromOAuth(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	namespace := "quickbooks"
	ctx, _ = appengine.Namespace(ctx, namespace)
	log.Println("Entering CallBackFromOAuth ")
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	realmId := r.URL.Query().Get("realmId")

	cache.AddToCache(ctx, "realmId", realmId)
	csrf := cache.GetFromCache(ctx, "csrf")
	//check whether the state returned in the redirect is same as the csrf sent
	if state == csrf {

		// retrive bearer token using code
		bearerTokenResponse, err := RetrieveBearerToken(ctx, code)
		if err != nil {
			log.Fatalln(err)
		}
		/*
		 * add token to cache
		 * In real usecase, this is where tokens would have to be persisted (to a SQL DB, for example).
		 * Update your Datastore here with user's AccessToken and RefreshToken along with the realmId
		 */
		cache.AddToCache(ctx, "access_token", bearerTokenResponse.AccessToken)
		cache.AddToCache(ctx, "refresh_token", bearerTokenResponse.RefreshToken)
		qbci := models.QuickbooksConnectionInfo{
			AccessToken:  bearerTokenResponse.AccessToken,
			RefreshToken: bearerTokenResponse.RefreshToken,
			RealmID:      realmId,
		}
		qbdatastore.UpdateQuickbooksConnectionInfo(ctx, &qbci)

		/*
		 * However, in case of OpenIdConnect, when you request OpenIdScopes during authorization,
		 * you will also receive IDToken from Intuit. You first need to validate that the IDToken actually came from Intuit.
		 */
		idToken := bearerTokenResponse.IdToken
		if idToken != "" {
			//validate id token
			if ValidateIDToken(ctx, idToken) {
				// get userinfo
				GetUserInfo(w, r, bearerTokenResponse.AccessToken)
			}
		}
		log.Println("Exiting CallBackFromOAuth ")
		http.Redirect(w, r, "/connected/", http.StatusFound)
	} else {
		log.Println("CSRF mismatch, expected: " + csrf + " recieved:" + state)
	}
}

/*
 * Call JWKS endpoint and retrieve the key values
 */
func CallJWKSAPI(ctx context.Context) (*JWKSResponse, error) {
	log.Println("Entering CallJWKSAPI ")
	client := &http.Client{}
	connData := qbdatastore.GetQuickbooksConnectionData(ctx)
	jwksEndpoint := connData.JWKSURI
	request, err := http.NewRequest("GET", jwksEndpoint, nil)
	if err != nil {
		log.Fatalln(err)
	}
	//set header
	request.Header.Set("accept", "application/json")

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Exiting CallJWKSAPI ")
	return getJWKSResponse([]byte(body))
}

type JWKSResponse struct {
	KEYS []Keys `json:"keys"`
}

type Keys struct {
	KTY string `json:"kty"`
	E   string `json:"e"`
	USE string `json:"use"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	N   string `json:"n"`
}

func getJWKSResponse(body []byte) (*JWKSResponse, error) {
	var s = new(JWKSResponse)
	err := json.Unmarshal(body, &s)
	if err != nil {
		log.Fatalln("error getting JWKSResponse:", err)
	}
	return s, err
}

/*
 * Method to retrive access token (bearer token)
 */
func RetrieveBearerToken(ctx context.Context, code string) (*BearerTokenResponse, error) {
	log.Println("Entering RetrieveBearerToken ")
	client := &http.Client{}
	data := url.Values{}
	//set parameters
	data.Set("grant_type", "authorization_code")
	data.Add("code", code)
	data.Add("redirect_uri", os.Getenv("REDIRECT_URI"))
	connData := qbdatastore.GetQuickbooksConnectionData(ctx)
	tokenEndpoint := connData.TokenEndpoint
	request, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		log.Fatalln(err)
	}
	//set headers
	request.Header.Set("accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	request.Header.Set("Authorization", "Basic "+basicAuth(ctx))

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	bearerTokenResponse, err := getBearerTokenResponse([]byte(body))
	log.Println("Exiting RetrieveBearerToken ")
	return bearerTokenResponse, err
}

/*
 * Method to validate IDToken
 */
func ValidateIDToken(ctx context.Context, idToken string) bool {

	log.Println("Ending ValidateIDToken")
	if idToken != "" {
		parts := strings.Split(idToken, ".")

		if len(parts) < 3 {
			log.Fatalln("Malformed ID token")
			return false
		}

		idTokenHeader, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			log.Fatalln("error parsing idTokenHeader:", err)
			return false
		}
		idTokenPayload, errr := base64.RawStdEncoding.DecodeString(parts[1])
		if errr != nil {
			log.Fatalln("error parsing idTokenPayload:", errr)
			return false
		}

		var payload = new(Claims)
		error := json.Unmarshal(idTokenPayload, &payload)
		if error != nil {
			log.Fatalln("error parsing payload:", error)
			return false
		}

		var header = new(Header)
		error1 := json.Unmarshal(idTokenHeader, &header)
		if error1 != nil {
			log.Fatalln("error parsing idTokenHeader:", error1)
			return false
		}

		connData := qbdatastore.GetQuickbooksConnectionData(ctx)

		//Step 1 : First check if the issuer is as mentioned in "issuer" in the discovery doc
		issuer := payload.ISS
		if issuer != connData.Issuer {
			log.Fatalln("issuer value mismtach")
			return false
		}

		//Step 2 : check if the aud field in idToken is same as application's clientId
		audArray := payload.AUD
		aud := audArray[0]
		if aud != os.Getenv("CLIENT_ID") {
			log.Fatalln("incorrect client id")
			return false
		}

		//Step 3 : ensure the timestamp has not elapsed
		expirationTimestamp := payload.EXP
		now := time.Now().Unix()
		if (expirationTimestamp - now) <= 0 {
			log.Fatalln("expirationTimestamp has elapsed")
			return false
		}

		//Step 4: Verify that the ID token is properly signed by the issuer
		jwksResponse, err := CallJWKSAPI(ctx)
		if err != nil {
			log.Fatalln("error calling jwks", err)
			return false
		}

		//check if keys[0] belongs to the right kid
		headerKid := header.KID
		if headerKid != jwksResponse.KEYS[0].KID {
			log.Fatalln("no keys found for the header ", err)
			return false
		}

		//get the exponent (e) and modulo (n) to form the PublicKey
		e := jwksResponse.KEYS[0].E
		n := jwksResponse.KEYS[0].N

		//build the public key
		pubKey, err := getPublicKey(n, e)
		if err != nil {
			log.Fatalln("unable to get public key", err)
			return false
		}

		//verify token using public key
		data := []byte(parts[0] + "." + parts[1])
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			log.Fatalln("error decoding tokensignature:", err)
			return false
		}
		if err := verify(signature, data, pubKey); err != nil {
			log.Fatalln("unable to verify signature", err)
			return false
		}

		log.Println("Token Signature validated")
		return true
	}
	log.Println("Exiting ValidateIDToken")
	return false
}

type Header struct {
	ALG string `json:"alg"`
	KID string `json:"kid"`
}
type Claims struct {
	AUD       []string `json:"aud"`
	EXP       int64    `json:"exp"`
	IAT       int      `json:"iat"`
	ISS       string   `json:"iss"`
	REALMID   string   `json:"realmid"`
	SUB       string   `json:"sub"`
	AUTH_TIME int      `json:"auth_time"`
}

/*
 * Build public key
 */
func getPublicKey(modulus, exponent string) (*rsa.PublicKey, error) {

	decN, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		log.Fatalln("error decoding modulus", err)
	}
	n := big.NewInt(0)
	n.SetBytes(decN)

	decE, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil {
		log.Fatalln("error decoding exponent", err)
	}
	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}
	eReader := bytes.NewReader(eBytes)
	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		log.Fatalln("error reading exponent", err)
	}

	s := rsa.PublicKey{N: n, E: int(e)}
	var pKey *rsa.PublicKey = &s
	return pKey, err

}

/*
 * verify token using public key
 */
func verify(signature, data []byte, pubKey *rsa.PublicKey) error {
	hash := sha256.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature); err != nil {
		return fmt.Errorf("unable to verify signature, %s", err.Error())
	}

	return nil
}

/*
 * Method to retrive userInfo - email, address, name, phone etc
 */
func GetUserInfo(w http.ResponseWriter, r *http.Request, accessToken string) (*UserInfoResponse, error) {
	ctx := appengine.NewContext(r)
	namespace := "quickbooks"
	ctx, _ = appengine.Namespace(ctx, namespace)
	log.Println("Inside GetUserInfo ")
	client := &http.Client{}

	connData := qbdatastore.GetQuickbooksConnectionData(ctx)
	userInfoEndpoint := connData.UserInfoEndpoint
	request, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		log.Fatalln(err)
	}
	//set header
	request.Header.Set("accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	userInfoResponse, err := getUserInfoResponse([]byte(body))
	//Adding to cache for illustration - Save info to datastore in your real app
	cache.AddToCache(ctx, "givenName", userInfoResponse.GivenName)
	cache.AddToCache(ctx, "email", userInfoResponse.Email)

	log.Println("Ending GetUserInfo")
	return userInfoResponse, err
}

type Address struct {
	StreetAddress string `json:"streetAddress"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postalCode"`
	Country       string `json:"country"`
}

type UserInfoResponse struct {
	Sub                 string  `json:"sub"`
	Email               string  `json:"email"`
	EmailVerified       bool    `json:"emailVerified"`
	GivenName           string  `json:"givenName"`
	FamilyName          string  `json:"familyName"`
	PhoneNumber         string  `json:"phoneNumber"`
	PhoneNumberVerified bool    `json:"phoneNumberVerified"`
	Address             Address `json:"address"`
}

func getUserInfoResponse(body []byte) (*UserInfoResponse, error) {
	var s = new(UserInfoResponse)
	err := json.Unmarshal(body, &s)
	if err != nil {
		log.Fatalln("error parsing userInfoResponse:", err)
	}
	return s, err
}

/*
 *  Call discovery document and populate the cache
 */
func CallDiscoveryAPI(ctx context.Context) {
	log.Println("Entering CallDiscoveryAPI ")
	client := &http.Client{}
	var qbci models.QuickbooksConnectionInfo
	request, err := http.NewRequest("GET", os.Getenv("DISCOVERY_API_HOST"), nil)
	if err != nil {
		log.Fatalln(err)
	}
	//set header
	request.Header.Set("accept", "application/json")

	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	discoveryAPIResponse, err := getDiscoveryAPIResponse([]byte(body))

	//Add the urls to cache - in real app, these should be stored in database or config repository
	cache.AddToCache(ctx, "authorization_endpoint", discoveryAPIResponse.AuthorizationEndpoint)
	cache.AddToCache(ctx, "token_endpoint", discoveryAPIResponse.TokenEndpoint)
	cache.AddToCache(ctx, "jwks_uri", discoveryAPIResponse.JwksUri)
	cache.AddToCache(ctx, "revocation_endpoint", discoveryAPIResponse.RevocationEndpoint)
	cache.AddToCache(ctx, "userinfo_endpoint", discoveryAPIResponse.UserinfoEndpoint)
	cache.AddToCache(ctx, "issuer", discoveryAPIResponse.Issuer)
	qbci = models.QuickbooksConnectionInfo{
		TokenEndpoint:         discoveryAPIResponse.TokenEndpoint,
		JWKSURI:               discoveryAPIResponse.JwksUri,
		AuthorizationEndpoint: discoveryAPIResponse.AuthorizationEndpoint,
		RevocationEndpoint:    discoveryAPIResponse.RevocationEndpoint,
		UserInfoEndpoint:      discoveryAPIResponse.UserinfoEndpoint,
		Issuer:                discoveryAPIResponse.Issuer,
	}
	qbdatastore.StoreQuickbooksConnectionData(ctx, &qbci)
	log.Println("Exiting CallDiscoveryAPI ")
}

type DiscoveryAPIResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}

func getDiscoveryAPIResponse(body []byte) (*DiscoveryAPIResponse, error) {
	var s = new(DiscoveryAPIResponse)
	err := json.Unmarshal(body, &s)
	if err != nil {
		log.Fatalln("error getting DiscoveryAPIResponse:", err)
	}
	return s, err
}
