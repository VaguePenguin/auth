package auth

import (
	// std libs
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	// external libs
	"cloud.google.com/go/firestore"
)

const contentTypeAppJSON = "application/json"

var ErrNotFound = errors.New("Not Found")

// RegisterUser registers a new user on the sundstedts site
func RegisterUser(host, username, password string) (*Authorization, error) {
	requestBody, err := json.Marshal(PassSet{
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(host+"/auth/register", contentTypeAppJSON, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	a := Authorization{}
	json.Unmarshal(body, &a)

	return &a, nil
}

// Login logs a user in
func Login(host, username, password string) (*Authorization, error) {
	requestBody, err := json.Marshal(PassSet{
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(host+"/auth/login", contentTypeAppJSON, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	a := Authorization{}
	json.Unmarshal(body, &a)

	return &a, nil
}

// GetToken - get user's token
func GetToken(r *http.Request, fClient *firestore.Client, host, cookieName string) (*Token, error) {
	ctx := r.Context()

	cookie, err := getCookie(ctx, r, fClient, host, cookieName)
	if err != nil {
		return nil, err
	}

	tl := cookie.tokenLocation

	resp, err := http.Get(host + "/auth/token/" + tl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	t := Token{}
	json.Unmarshal(body, &t)

	return &t, nil
}

// GetUserInfo - get user's info
func GetUserInfo(r *http.Request, fClient *firestore.Client, host, cookieName string) (*UserInfo, error) {
	ctx := r.Context()

	var ui UserInfo

	cookie, err := getCookie(ctx, r, fClient, host, cookieName)
	if err != nil {
		return nil, err
	}

	ui.UserID = cookie.userID

	tl := cookie.tokenLocation

	resp, err := http.Get(host + "/auth/token/" + tl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	t := Token{}
	json.Unmarshal(body, &t)

	ui.Token = t

	return &ui, nil
}

