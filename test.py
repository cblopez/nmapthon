import nmapthon as nm

engine = nm.engine.PyNSEEngine()


@engine.port_script('test', 8021)
def test():
    return 'A simple test!'


sc = nm.NmapScanner('www.youtube.com', arguments='-p66666', engine=engine)
sc.run()

