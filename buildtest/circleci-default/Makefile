# we use a twist on the default rules: scrape the packages and distro from
# the CircleCI config
# FIXME: the rest of the logic is duplicated so liable to shift... ideally
# we would generate more
Dockerfile.env: ../../.circleci/config.yml
	cat $< | awk -f scrape-circleci.awk > $@ || (rm -f $@; false)
