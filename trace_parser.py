import os
import sys
import subprocess
import binascii
import json

from http_node import HTTPNode

def run_command(command, ret_all):
    p = subprocess.Popen(args = command, 
                         stdout = subprocess.PIPE, 
                         stderr = subprocess.STDOUT,
                         shell = True)
    if not ret_all:
        return iter(p.stdout.readline, b'');
    else:
        return p.stdout.readlines()

def get_frame_sequence(captured_file):
    """
    Given a pcap file,
    return an ordered list of http node, each is identified by a unique frame number
    """
    frame_seq = []
    get_all_frame = "tshark -r {} -Y 'http.request || http.response' -T fields -e frame.number".format(captured_file)
    frames = run_command(get_all_frame, True)
    for f in frames:
        fn = int(f.decode('utf8').rstrip('\n'))
        frame_seq.append(HTTPNode(fn))
        
    return frame_seq
   
def pair_frame(captured_file, frame_seq):
    """
    Given a pcap file,
    return:
    frame_seq: the trace, ordered list of http node, each of which represents either a request or a response
    fs_relation: tcp stream number, mapping to a list of rids belong to this stream
    """
    rid = 0
    all_frame = {}
    fs_relation = {}  # frame_stream_relation, mapping from stream number to one or more rid
    get_pairing = "tshark -2 -r {} -R '' -Y 'frame.number > 0 && http.request' -T fields -e tcp.stream -e frame.number -e http.response_in"
    
    # Run get_pairing command
    pairs = run_command(get_pairing.format(captured_file), False)

    # Associate each request and response node with its frame number in a dict
    for i in range(0, len(frame_seq)):
        cur_node = frame_seq[i]
        all_frame[cur_node.get_frame()] = cur_node
    
    all_stream = []
    for p in pairs:
        pl = p.decode('utf8').rstrip('\n').split('\t')
        cur_sn = int(pl[0])   # current_stream_number
        try:
            fs_relation[cur_sn]
        except KeyError:
            fs_relation[cur_sn] = []
        all_stream.append(cur_sn)
        fs_relation[cur_sn].append(rid)

        req_fn = int(pl[1])   # request_frame
        all_frame[req_fn].set_req()
        all_frame[req_fn].set_rid(rid)

        try:
            res_fn = int(pl[2])   # response_frame
            all_frame[res_fn].set_res()
            all_frame[res_fn].set_rid(rid)
        except ValueError:
            # Handle request without response here
            pass

        rid += 1

    return frame_seq, fs_relation, all_stream


def get_all_trace(captured_file, stream_nums, fs_relation):
    
    all_res = {}
    all_req = {}
    for num in stream_nums:
        s_res, s_req = get_trace(captured_file, num, fs_relation[num])
        all_res.update(s_res)
        all_req.update(s_req)

    return all_res, all_req

def get_trace(captured_file, stream_num, rids):
    """
    Takes the captured file, a tcp stream number, and the pre-assigned rids
    separate all the request/response content in that stream,
    associate each req-res pair with a unique rid
    store the req and req separately in two array of dict, and return these two array
    """
    follow_stream = "tshark -q -r {} -z follow,tcp,raw,{}".format(captured_file, stream_num)
    stream_content = run_command(follow_stream, True)
    stream_all_res, stream_all_req = get_req_res(stream_content, rids)

    return stream_all_res, stream_all_req

def get_req_res(stream_content, rids):
    """
    Stream_content could contain multiple req/res pairs,
    each of them has the following format:
    index 0,1,-1: separator
    index 2 - 5 : metadata
    index > 5   : request and response (separate by checking the '\t')
    
    tshark has a natural separation of req/res by adding '\t' to each response packet
    tshark adds a '\n' to every packet (each packet has its own index in stream_content list)
    """
    req_node = stream_content[4]
    res_node = stream_content[5]
    all_req = {}
    all_res = {}
    cur_req = b''
    cur_res = b''
    encounter_start = True
    encounter_end = False
    r = 0

    for i in range(6, len(stream_content)-1):
        content = stream_content[i]
        start_byte = content[0]
        content = content.decode('utf8').rstrip('\n')

        if start_byte != ord('\t'):
            in_req = True
        else:
            in_req = False
            encounter_start = True

        # The start of a new req/res pair round
        if encounter_start and in_req:
            if len(cur_req) != 0 and len(cur_res) != 0:
                all_req[rids[r]] = cur_req
                all_res[rids[r]] = cur_res
                r += 1

            cur_req = b''
            cur_res = b''

            encounter_start = False

        if start_byte != ord('\t'):
            cur_req += content.encode('utf8')
        else:
            cur_res += content.lstrip('\t').encode('utf8')
    
    # Add the last/the only pair of req/res pair in this stream
    all_req[rids[r]] = cur_req
    all_res[rids[r]] = cur_res
        
    return all_req, all_res

def parse_res_id(response):
    """
    This function should take a response and parse the rid from the header
    """
    pass

def get_trace_json(trace):
    trace_json = []
    for t in trace:
        tn = {}
        tn["rid"] = t.get_rid()
        tn["type"] = "request" if t.is_req() else "response"
        trace_json.append(tn)
    return trace_json

def dump_json(obj, file_path):
    try:
        fp = open(file_path, "w")
    except IOError:
        print("Unable to open {}\n".format(file_path))        
    json.dump(obj, fp, ensure_ascii=False)

def parse_trace():
    captured_file = sys.argv[1]
    frame_seq = get_frame_sequence(captured_file)
    trace, fs_relation, all_stream = pair_frame(captured_file, frame_seq)
    
    dump_json(get_trace_json(trace), "trace.json")
    all_req, all_res = get_all_trace(captured_file, all_stream, fs_relation)
    
    for req in all_req:
        print(req, all_req[req])
        #print (req, binascii.a2b_hex(all_req[req]))
    for res in all_res:
        print(res, all_res[res])
        #print(res, binascii.a2b_hex(all_res[res]))

    # How to store them?
    # dump_json(all_req, "requests.json")
    # dump_json(all_res, "responses.json")
    
if __name__ == "__main__":
    parse_trace()
    
