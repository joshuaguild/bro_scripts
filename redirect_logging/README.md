# Redirect Logging
**redirect_logging.bro** - Logs and displays information from the http.log but includes a redirected_to column that pulls the Location value of the server response. The idea here is to help traffic as it bounces through redirects. It'll go bananas with ads but what can ya do.

TODO: this is kind of hacky and I'd like to just **add** a column to the http.log - working on it.
