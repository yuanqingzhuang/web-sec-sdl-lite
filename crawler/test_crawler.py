from crawler.engine import BasicCrawler

if __name__ == "__main__":
    crawler = BasicCrawler("http://127.0.0.1:5000", max_pages=1000)
    result = crawler.crawl()
    crawler.save_results(result, "results/crawl_output.json")
    print(result)
