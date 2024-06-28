if __name__ == '__main__':
    baselines = Path('./baselines').resolve()
    b = read_baseline_docs(baselines)

    print(json.dumps(b, indent=4))