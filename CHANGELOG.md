Increment version number 
<br/>
Optimize server_event_loop function to use stop_server function and remove unneeded parameter
<br/>
Edit start_server function so that server_event_loop is run in a different thread if not being run interactively