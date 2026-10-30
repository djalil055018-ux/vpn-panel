package store

import "testing"

func TestNativeBotSubscriptionBase(t *testing.T) {
	for _, value := range []string{"https://panel.example.com/sub/", "https://panel.example.com:9443/sub/"} {
		if !validNativeSubscriptionBase(value) {
			t.Fatal("valid independent origin rejected")
		}
	}
	for _, value := range []string{"http://panel.example.com/sub/", "https://user:password@panel.example.com/sub/", "https://panel.example.com/sub/?token=secret", "https://panel.example.com/sub/#fragment", "https://panel.example.com/sub/?", "https://panel.example.com/other/", "https:///sub/", "https://panel.example.com/%73ub/", "https://panel.example.com/sub/\n"} {
		if validNativeSubscriptionBase(value) {
			t.Fatal("unsafe origin accepted")
		}
	}
}
