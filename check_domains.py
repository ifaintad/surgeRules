from multiprocessing.pool import ThreadPool
from dns.exception import DNSException
from dns.resolver import resolve as dns_resolve
from tqdm import tqdm


def get_invalid_domains(domain_list, timeout=3, tries=3, concurrent=50,
                        output_file="invalid.txt"):

    progress_bar = tqdm(
        total=len(domain_list),
        desc='collect invalid domains', unit='domains', position=0, leave=True)

    def callback(_url):
        if _url is not None:
            with open(output_file, 'a') as f:
                f.write('{}\n'.format(_url))

    def check_invalid_url(_url, _timeout=3, _tries=3):
        progress_bar.update(1)
        for _ in range(0, _tries):
            try:
                dns_resolve(_url, "A", lifetime=_timeout)
                return None
            except (DNSException, ValueError):
                try:
                    dns_resolve(_url, "NS", lifetime=_timeout)
                    return None
                except (DNSException, ValueError):
                    pass

        return _url

    # create a thread pool and start the workers
    thread_pool = ThreadPool(concurrent)
    workers = []

    for url in domain_list:
        w = thread_pool.apply_async(
            check_invalid_url,
            (url, timeout, tries),
            callback=callback)
        workers.append(w)

    # ensure all workers complete
    for w in workers:
        w.get()

    thread_pool.close()
    thread_pool.join()
    progress_bar.close()

    with open(output_file, "r") as f:
        ret = set([r for r in f.read().split("\n") if r])

    with open(output_file, "w") as f:
        f.write("\n".join(sorted(list(ret))))

    return ret
