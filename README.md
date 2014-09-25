change_server
=============

Nginx module which change server name in one request


## Directives

Syntax: **change_server**

Default: `none`

Context: `location, if location`

Description: `If it is set 'change_server', request will be redirect to new_server_name in conf. If new_server_name is not found, it will be processed in default server name.`


###Example

	server {
		listen       80;
		server_name  localhost;
		location / {
			change_server new;
		}
	}
	
	server {
		listen       80;
		server_name  new;
		location / {
			#do anything ...
		}
	}

