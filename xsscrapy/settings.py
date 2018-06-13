#coding=utf-8
#
#     http://doc.scrapy.org/en/latest/topics/settings.html
#

# Uncomment below in order to disallow redirects
#REDIRECT_ENABLED = False

# Uncomment this to lessen the spider's output
#LOG_LEVEL = 'INFO'

BOT_NAME = 'xsscrapy'

SPIDER_MODULES = ['xsscrapy.spiders']
NEWSPIDER_MODULE = 'xsscrapy.spiders'

# For adding javascript rendering
#DOWNLOAD_HANDLERS = {'http':'xsscrapy.scrapyjs.dhandler.WebkitDownloadHandler',
#                     'https': 'xsscrapy.scrapyjs.dhandler.WebkitDownloadHandler'}

# 100 (first): Make sure there's no duplicate requests that have some value changed
# 200 (second): Make sure there's a random working User-Agent header set if that value's not injected with the test string
DOWNLOADER_MIDDLEWARES = {'xsscrapy.middlewares.InjectedDupeFilter': 100,
                          'xsscrapy.middlewares.RandomUserAgentMiddleware': 200,
                          'scrapy.contrib.downloadermiddleware.httpauth.HttpAuthMiddleware': 300}

COOKIES_ENABLED = True
#COOKIES_DEBUG = True

# Prevent duplicate link crawling
# Bloom filters are way more memory efficient than just a hash lookup
DUPEFILTER_CLASS = 'xsscrapy.bloomfilters.BloomURLDupeFilter'
#DUPEFILTER_CLASS = 'scrapy.dupefilter.RFPDupeFilter'

ITEM_PIPELINES = {'xsscrapy.pipelines.XSSCharFinder':100,


#'xsscrapy.pipelines.RedisPipeline':400,
}

#FEED_FORMAT = 'csv'
#FEED_URI = 'example.txt'

CONCURRENT_REQUESTS = 10
DOWNLOAD_DELAY = 5

REACTOR_THREADPOOL_MAXSIZE = 5

DOWNLOADER_MIDDLEWARES = {
    'xsscrapy.JSMiddleware.PhantomJSMiddleware': 100
}

#预判打印错误日志时可用。
#LOG_ENABLED = True
#LOG_FILE = "xxxcrapy_error.log"
#LOG_LEVEL = "ERROR"

""" SCHEDULER = "scrapy_redis.scheduler.Scheduler"
SCHEDULER_PERSIST = True
SCHEDULER_QUEUE_CLASS = 'scrapy_redis.queue.SpiderPriorityQueue'
REDIS_URL = 'redis://192.168.14.129:6379'
REDIS_HOST = '192.168.14.129'
REDIS_PORT = 6379
DUPEFILTER_CLASS = "scrapy_redis.dupefilter.RFPDupeFilter"
 """

'''pipline 传参确实传不进去，这里默认设置多少s后，spider任务开始停止。
多任务无法暂时单个计算超时，xxxcrapy实现了多url添加，但如果需要单独运行，需要禁用这里的CLOSESPIDER_TIMEOUT。
想要实现多url添加，并且实现任务量控制，以及多url的时间控制，需要借用hellsrc。'''

CLOSESPIDER_TIMEOUT = 10