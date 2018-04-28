#coding=utf-8
from selenium import webdriver
import scrapy
from scrapy.http import HtmlResponse
js = '''
function scrollToBottom() {

    var Height = document.body.clientHeight,  //文本高度
        screenHeight = window.innerHeight,  //屏幕高度
        INTERVAL = 100,  // 滚动动作之间的间隔时间
        delta = 500,  //每次滚动距离
        curScrollTop = 0;    //当前window.scrollTop 值

    var scroll = function () {
        curScrollTop = document.body.scrollTop;
        window.scrollTo(0,curScrollTop + delta);
    };

    var timer = setInterval(function () {
        var curHeight = curScrollTop + screenHeight;
        if (curHeight >= Height){   //滚动到页面底部时，结束滚动
            clearInterval(timer);
        }
        scroll();
    }, INTERVAL)
}

'''

class PhantomJSMiddleware(object):
    @classmethod
    def process_request(cls, request, spider):
        if request.meta.has_key('PhantomJS'):
            driver = webdriver.PhantomJS() 
            driver.get(request.url)
            driver.execute_script(js)   
            #time.sleep(1)  # 等待JS执行
            driver.implicitly_wait(10)
            content = ""
            try:
                content = driver.page_source.encode('utf-8')
            except Exception, e:
                print e
                content = driver.page_source.encode("GBK", "ignore");
            driver.quit()  
            return HtmlResponse(request.url, encoding='utf-8', body=content, request=request)