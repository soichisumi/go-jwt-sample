package go_jwt_sample

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
	"log"
	"testing"
	"time"
)

const (
	rsaPrivateKeyPath = "./privKey.pem"
	rsaPublicKeyPath = "./privKey.pem.pub.pkcs8"
)

func Test_JWT(t *testing.T) {
	// load keys
	privKey, err := ioutil.ReadFile(rsaPrivateKeyPath)
	if err != nil {
		log.Fatalf("Error reading the jwt private key: %s", err)
	}
	parsedPrivKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKey)
	if err != nil {
		log.Fatalf("Error parsing the jwt private key: %s", err)
	}

	pubKey, err := ioutil.ReadFile(rsaPublicKeyPath)
	if err != nil {
		log.Fatalf("Error reading the jwt public key: %s", err)
	}
	parsedPubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKey)
	if err != nil {
		log.Fatalf("Error parsing the jwt public key: %s", err)
	}

	Convey("generate token", t, func(){


		token := jwt.New(jwt.SigningMethodRS256)

		// set claims
		claims := token.Claims.(jwt.MapClaims)
		claims["role"] = 1 // admin
		claims["exp"] = time.Now().Add(time.Hour * 24 * 365 * 3).Unix()

		tokenString, err := token.SignedString(parsedPrivKey)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("token: " + tokenString)
	})

	Convey("parse token", t, func(){
		tokenStr := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDU0MzMyODYsInJvbGUiOjF9.Jok7_6ntOgS2kJyKH0RoNEA_SEibvdqLW9xs-ZqZ8tOoTkYeSFFKSmCwu-dpcnrtcOaMdfh0DEHTTvDhwYDYMOrvfN0Vc721bOqOMFJKavLTpWvX7cHKADjyKICVi8r7VnO0LM9UxZdfn83EPjgyoVSxNWnEyaGwoiTXBuv8MmJ8c6Kst_qiIsfIHFbRYxqRBMsWeig3zRDeqi97QrpMO54fDHH8BAbODBe5pO50UoO9lrMB4kKWyZRQDmfF0k_jWIas5Ro0v-iLaNqML8DIQfMHMW6eOZxI_YKk8WOpHjPMSWtNy40vMn4DC6GHcXmTR256OVw0imxNbG4x99oVIt9Nkkh_n3K2J-Q2Qfkejnhma7PZpJ6dAZ5yky_C-gtkKKyYs5WXIzHm0g8PxNs65HD6KTzfEOaVbytKCp0jFtIgan8chxSil0RZ4u0upyW36G_kEK7xE2xniKd6XagpZ0vd2J35Nb3yNmvDxkCt_RyYul5EJoxI3IKbTra0KkqVl9_cx8ePrH32IONmpMIPeUhYQSoVlg59TzTApTJgii6Pd0OOFsZXSJ-DKq9VJzA2Edl_OvO5qpytQXR0KTfR4XHe_XL2ezUtg5-Ow_9lJA6miv3SKGniOGM1q-W4JUFzKcSkedFLfB46X35s5C-mhlI7Xgy7cdudFdMPQOYequM"
		jwtToken, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				log.Printf("Unexpected signing method: %v", t.Header["alg"])
				return nil, fmt.Errorf("invalid token")
			}
			return parsedPubKey, nil
		})
		So(err, ShouldBeNil)

		So(jwtToken.Method, ShouldResemble, jwt.SigningMethodRS256)
		claims, ok := jwtToken.Claims.(jwt.MapClaims)
		So(ok, ShouldBeTrue)

		roleStr, ok := claims["role"].(float64)

		So(ok, ShouldBeTrue)
		So(uint32(roleStr), ShouldEqual, 1)
	})

	//jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
	//	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
	//		log.Printf("Unexpected signing method: %v", t.Header["alg"])
	//		return nil, fmt.Errorf("invalid token")
	//	}
	//	return pubKey, nil
	//})
	//if err == nil && jwtToken.Valid {
	//	return jwtToken, nil
	//}
}