### Snyk Webhook in progress example

This is an example webhook receiver that includes a mock webhook trigger in the examples/ directory

This is not definitive and refer to the beta documentation for the latest info.

[https://webhook.site/](https://webhook.site/) is a great resource to see the live payloads as they are submitted, including headers and where the examples json files representing the payload contents were originally copied from. Visit that link, use the provided url under "Your unique URL" when setting up the webhook and the site will reload with the payloads as they arrive.

The app/main.py example is a fastapi based webhook receiver that just does some flattening of a webhook and responds with the result - useful to pair with the examples/submit_hook.py script if you're fine tuning how you want to parse a webhook.

