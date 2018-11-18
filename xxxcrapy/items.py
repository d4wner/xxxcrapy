# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

from scrapy.item import Item, Field

class vuln(Item):
    unfiltered = Field()
    xss_payload = Field()
    xss_place = Field()
    inj_tag = Field()
    orig_url = Field()
    resp_url = Field()
    xss_param = Field()
    error = Field()
    sugg_payloads = Field()
    line = Field()
    POST_to = Field()
    post_paras = Field()
    #form_method = Field()
    #form_base_url = Field()


    def __str__(self):
        ''' Prevent the item from being printed to output during debugging '''
        return ''

class inj_resp(Item):
    resp = Field()

    def __str__(self):
        ''' Prevent the item from being printed to output during debugging '''
        return ''
