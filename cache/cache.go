package cache

import (
	"context"
	"google.golang.org/appengine/v2/memcache"
)

func AddToCache(ctx context.Context, key, value string) {
	item1 := &memcache.Item{
		Key:   key,
		Value: []byte(value),
	}
	if err := memcache.Set(ctx, item1); err != nil {
		panic(err)
	}
}

func GetFromCache(ctx context.Context, key string) string {
	item0, err := memcache.Get(ctx, key)
	if err != nil && err != memcache.ErrCacheMiss {
		return ""
	} else if err == memcache.ErrCacheMiss {
		return ""
	} else {
		return string(item0.Value)
	}
}
