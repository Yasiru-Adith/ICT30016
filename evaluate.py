import argparse
import json
import sqlite3
from statistics import mean


def main():
    p = argparse.ArgumentParser(description='Record a separately labelled trial and report rates')
    p.add_argument('--database', required=True)
    p.add_argument('--trial-id', required=True)
    p.add_argument('--scenario', required=True)
    p.add_argument('--rule', required=True)
    p.add_argument('--label', choices=['attack','normal'], required=True)
    p.add_argument('--start', required=True, help='UTC ISO timestamp of actual test start')
    p.add_argument('--end', required=True, help='UTC ISO timestamp of actual test end')
    args = p.parse_args()
    from edr.core import timestamp, utc
    start, end = timestamp(args.start), timestamp(args.end)
    if end <= start:
        p.error('End must be after start')
    db = sqlite3.connect(args.database)
    try:
        alerts = [json.loads(row[0]) for row in db.execute('SELECT payload FROM alerts')]
        matched = [a for a in alerts if a['rule_id']==args.rule and not a.get('synthetic') and start <= timestamp(a['detection_timestamp']) <= end]
        trials = [json.loads(row[0]) for row in db.execute('SELECT payload FROM trials')]
        if any(t['trial_id']==args.trial_id for t in trials):
            p.error('Trial ID already exists')
        if any(t['rule_id']==args.rule and start < timestamp(t['end']) and end > timestamp(t['start']) for t in trials):
            p.error('Trial windows must not overlap for the same rule')
        value = {'trial_id':args.trial_id,'scenario':args.scenario,'rule_id':args.rule,
                 'label':args.label,'start':args.start,'end':args.end,'detected':bool(matched),
                 'ttd_seconds':min(timestamp(a['detection_timestamp'])-start for a in matched) if matched else None}
        with db:
            db.execute('INSERT INTO trials(recorded,payload) VALUES (?,?)',(utc(),json.dumps(value)))
        trials.append(value)
        subset = [t for t in trials if t['scenario']==args.scenario and t['rule_id']==args.rule]
        tp=sum(t['label']=='attack' and t['detected'] for t in subset)
        fn=sum(t['label']=='attack' and not t['detected'] for t in subset)
        fp=sum(t['label']=='normal' and t['detected'] for t in subset)
        tn=sum(t['label']=='normal' and not t['detected'] for t in subset)
        timing=[t['ttd_seconds'] for t in subset if t['label']=='attack' and t['detected']]
        print(json.dumps({'scenario':args.scenario,'TP':tp,'FN':fn,'FP':fp,'TN':tn,
                          'detection_rate':tp/(tp+fn) if tp+fn else None,
                          'false_positive_rate':fp/(fp+tn) if fp+tn else None,
                          'mttd_seconds_detected_trials_only':mean(timing) if timing else None}, indent=2))
    finally:
        db.close()

if __name__ == '__main__':
    main()
