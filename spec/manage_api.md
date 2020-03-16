Manage API 
==========

### Auth log

	GET /api/manage/authlog

	Query parameters:
		user_id=5e4d327c5797ab000140c87c   // user id for retrieving logs (required)
	  pagination
		count=100                          // response size (default 1000, max 10000)
		from=5e4d327c5797ab000140c880      // last record id for previous page

Examples:

	https://localhost/api/manage/authlog?user_id=5e4bf686ec27360001d36517&from=5e6b5956dddb0f00011b5eec

	[
		{
			"id": "5e6b763ffac81e0001a9f601",
			"timestamp": "2020-03-13T12:02:07.146Z",
			"action_type": "auth",
			"app_id": "5e410c64184851000189ec01",
			"app_name": "Test",
			"user_id": "5e4bf686ec27360001d36517",
			"user_identity_id": "5e4bf686ec27360001d36518",
			"ProviderID": "5e410c64184851000189ec02",
			"provider_name": "initial",
			"referer": "https://id.tst.qilin.super.com/sign-in?login_challenge=d520054eb23d4dc4b8c55a9d08bb719d",
			"useragent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/80.0.3987.87 Chrome/80.0.3987.87 Safari/537.36",
			"ip": "194.190.17.173",
			"ip_info": {
				"country": "Russia",
				"city": "Moscow",
				"subdivision": [ "Moscow" ]
			},
			"client_time": "1970-01-01T00:00:00Z"
		}
	]
