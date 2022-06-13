package qbdatastore

import (
	"context"
	"github.com/FreeMomHugs/quickbooks/models"
	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/datastore"
	"log"
	"os"
)

func GetQuickbooksConnectionData(ctx context.Context) *models.QuickbooksConnectionInfo {
	ctx, _ = appengine.Namespace(ctx, os.Getenv("NAMESPACE"))
	key := datastore.NewKey(ctx, "QuickbooksConnectionInfo", "", 5647851442929664, nil)
	var x models.QuickbooksConnectionInfo
	err := datastore.Get(ctx, key, &x)
	if err != nil {
		log.Println("Error getting connection info: " + err.Error())
	}
	return &x
}

func StoreQuickbooksConnectionData(ctx context.Context, qb *models.QuickbooksConnectionInfo) {
	ctx, namerr := appengine.Namespace(ctx, os.Getenv("NAMESPACE"))
	if namerr != nil {
		log.Println("error setting namespace: " + namerr.Error())
	}
	q := datastore.NewQuery("QuickbooksConnectionInfo")
	var x models.QuickbooksConnectionInfo
	for t := q.Run(ctx); ; {
		key, err := t.Next(&x)
		if err == datastore.Done {
			if x.Issuer == "" {
				_, dserr := datastore.Put(ctx, datastore.NewIncompleteKey(ctx, "QuickbooksConnectionInfo", nil), qb)
				if dserr != nil {
					log.Println("error updating QB connection info: " + err.Error())
				}
			}
			break
		} else {
			_, err := datastore.Put(ctx, key, qb)
			if err != nil {
				log.Println("error updating QB connection info: " + err.Error())
			}
		}
		if err != nil {
			panic(err)
		}
	}
}

func StoreAccountsInfo(ctx context.Context, accounts *models.AccountsQueryResults) {
	for _, account := range accounts.QueryResponse.Account {
		_, dserr := datastore.Put(ctx, datastore.NewIncompleteKey(ctx, "QuickbooksAccount", nil), &account)
		if dserr != nil {
			log.Println("error while writing account info: " + dserr.Error())
		}
	}
}

func UpdateAccountsInfo(ctx context.Context, accounts *models.AccountsQueryResults) {
	ctx, _ = appengine.Namespace(ctx, os.Getenv("NAMESPACE"))
	for _, account := range accounts.QueryResponse.Account {
		q := datastore.NewQuery("QuickbooksAccount").Filter("ID=", account.ID)
		var x models.QBAccount
		for t := q.Run(ctx); ; {
			key, err := t.Next(&x)
			x.CurrentBalance = account.CurrentBalance
			x.Name = account.Name
			x.FullyQualifiedName = account.FullyQualifiedName
			if err == datastore.Done {
				break
			}
			_, dserr := datastore.Put(ctx, key, &x)
			if dserr != nil {
				log.Println("error while writing account info: " + dserr.Error())
			}
		}

	}
}

func UpdateQuickbooksConnectionInfo(ctx context.Context, qb *models.QuickbooksConnectionInfo) {
	ctx, _ = appengine.Namespace(ctx, os.Getenv("NAMESPACE"))
	q := datastore.NewQuery("QuickbooksConnectionInfo")
	var x models.QuickbooksConnectionInfo
	for t := q.Run(ctx); ; {
		key, err := t.Next(&x)
		if err == datastore.Done {
			break
		} else {
			if qb.RealmID != "" {
				x.RealmID = qb.RealmID
			}
			if qb.RefreshToken != "" {
				x.RefreshToken = qb.RefreshToken
			}
			if qb.AccessToken != "" {
				x.AccessToken = qb.AccessToken
			}
			_, dserr := datastore.Put(ctx, key, &x)
			if dserr != nil {
				log.Println("error updating QB connection info: " + dserr.Error())
			}

		}
		if err != nil {
			panic(err)
		}
	}
}

func GetRefreshToken(ctx context.Context) string {
	ctx, _ = appengine.Namespace(ctx, os.Getenv("NAMESPACE"))
	q := datastore.NewQuery("QuickbooksConnectionInfo")
	var x models.QuickbooksConnectionInfo
	for t := q.Run(ctx); ; {
		_, err := t.Next(&x)
		if err == datastore.Done {
			break
		} else {
			return x.RefreshToken
		}
	}
	return ""
}

func GetAccountBalanceByID(ctx context.Context, ID string) float64 {
	ctx, _ = appengine.Namespace(ctx, os.Getenv("NAMESPACE"))
	q := datastore.NewQuery("QuickbooksAccount").Filter("ID=", ID)
	var x models.QBAccount
	for t := q.Run(ctx); ; {
		_, err := t.Next(&x)
		if err == datastore.Done {
			break
		} else {
			return x.CurrentBalance
		}
	}
	return 0
}
