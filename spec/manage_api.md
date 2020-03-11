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

	http://localhost:7001/api/manage/authlog?user_id=5e4d327c5797ab000140c87c

	[
		{
			"id": "5e4d327c5797ab000140c880",
			"timestamp": "0001-01-01T00:00:00Z",
			"action_type": "",
			"app_id": "",
			"app_name": "",
			"user_id": "5e4d327c5797ab000140c87c",
			"user_identity_id": "",
			"ProviderID": "",
			"provider_name": "",
			"referer": "",
			"useragent": "",
			"ip": "",
			"client_time": "0001-01-01T00:00:00Z"
		},
		{
			"id": "5e54d2e3ad498e0001271899",
			"timestamp": "0001-01-01T00:00:00Z",
			"action_type": "",
			"app_id": "",
			"app_name": "",
			"user_id": "5e4d327c5797ab000140c87c",
			"user_identity_id": "",
			"ProviderID": "",
			"provider_name": "",
			"referer": "",
			"useragent": "",
			"ip": "",
			"client_time": "0001-01-01T00:00:00Z"
		}
	]	

