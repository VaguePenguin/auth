package auth

import (
	// std libs
	"context"
	"net/http"
	"time"

	// external libs
	"cloud.google.com/go/firestore"

	"github.com/gorilla/securecookie"
)

var hashKey []byte

// SetCookie creates a secured http cookie that stores the location of the user's claims token
func SetCookie(ctx context.Context, w http.ResponseWriter, fClient *firestore.Client, host, userID, tokenLocation, cookieName, domain string) error {
	ck := fetchCookieKey(ctx, fClient)
	if ck == "" {
		return ErrNotFound
	}

	s := securecookie.New([]byte(ck), nil)

	v := map[string]string{
		"userID":        userID,
		"tokenLocation": tokenLocation,
	}

	encoded, err := s.Encode(cookieName, v)
	if err == nil {
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    encoded,
			Domain:   domain,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}

	return nil
}

// UnsetCookie removes the cookie for this user
func UnsetCookie(w http.ResponseWriter, cookieName, domain string) {
	c := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Domain:   domain,
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, c)
}

func fetchCookieKey(ctx context.Context, fClient *firestore.Client) string {
	ck, err := fClient.Collection("Secrets").Doc("CookieKey").Get(ctx)
	if err != nil {
		return ""
	}
	ckData := ck.Data()
	key := ckData["key"]
	if key == nil {
		return ""
	}

	ckm := key.(string)

	return ckm
}

func getCookie(ctx context.Context, r *http.Request, fClient *firestore.Client, host, cookieName string) (*userCookie, error) {
	ck := fetchCookieKey(ctx, fClient)
	if ck == "" {
		return nil, ErrNotFound
	}

	s := securecookie.New([]byte(ck), nil)
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, ErrNotFound
	}

	val := make(map[string]string)
	err = s.Decode(cookieName, cookie.Value, &val)
	if err != nil {
		return nil, err
	}

	u := userCookie{
		userID:        val["userID"],
		tokenLocation: val["tokenLocation"],
	}

	return &u, nil
}
