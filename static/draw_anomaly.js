/**
 * Draw router-level topologies and network-level topologies for anomaly localization and anomaly origin ranking
 * Created by Chen Wang on 6/8/2017.
 */

function include(arr,obj) {
    return (arr.indexOf(obj) != -1);
}

/**
 * @function drawAnomalyRouterTopology (network_id)
 * @description Draw the router level topology for a certain QoE anomaly that shows suspect nodes in yellow
 * @param anomaly_id: the id of the anomaly to study
 */
function drawAnomalyRouterTopology(anomaly_id, divTag) {
    var EDGE_LENGTH_MAIN = 50;
    var EDGE_LENGTH_SUB = 10;
    var url = '/diag/get_ano_graph_json?id=' + anomaly_id.toString();
    console.log(url);
    $.getJSON(url, function (json) {
        var org_nodes = json['nodes'];
        var nodes = [];

        // Create a data table with links.
        var links = json['links'];
        var edges = [];

        var nodeNumber = org_nodes.length;
        for (var i = 0; i < nodeNumber; i++) {
            nodes.push({
                id: i,
                nodeid: org_nodes[i]['id'],
                // label: "QoE: " + org_nodes[i]['qoe'].toPrecision(3),
                label: org_nodes[i]['name'],
                type: org_nodes[i]['type'],
                image: "/static/" + org_nodes[i]['group'] + "-" + org_nodes[i]['type'] + ".png",
                shape: 'image'
            });
        }

        var edgeNumber = links.length;
        for (var j = 0; j < edgeNumber; j++) {
            edges.push({from: links[j]['source'], to: links[j]['target'], length: EDGE_LENGTH_SUB})
        }

        // create a network
        var container = document.getElementById(divTag);
        var data = {
            nodes: nodes,
            edges: edges
        };
        var options = {
            layout: {
                improvedLayout:true,
                hierarchical: {
                    enabled:false,
                    direction: "RL"
                }
            }
        };
        network = new vis.Network(container, data, options);
        network.on('selectNode', function (params) {
            console.log(params);
            var nodeID = params['nodes'][0];
            console.log(nodeID);
            var node = nodes[nodeID];
            console.log(node);
            var url = "/diag/";
            console.log(url);
            document.location.href=url + "get_node?id=" + node['nodeid'];
        });
    });
}

/**
 * @function drawAnomalyNetworkTopology (anomaly_id, divTag)
 * @description Draw the network level topology for a certain QoE anomaly that shows suspect networks/devices in yellow
 * @param anomaly_id: the id of the anomaly to study
 */
function drawAnomalyNetworkTopology(anomaly_id, divTag) {
    var EDGE_LENGTH_MAIN = 50;
    var EDGE_LENGTH_SUB = 10;
    var url = '/diag/get_ano_network_topology_json?id=' + anomaly_id.toString();
    console.log(url);
    $.getJSON(url, function (json) {
        var org_nodes = json['nodes'];
        var nodes = [];

        // Create a data table with links.
        var links = json['links'];
        var edges = [];

        var nodeNumber = org_nodes.length;
        for (var i = 0; i < nodeNumber; i++) {
            nodes.push({
                id: i,
                nodeid: org_nodes[i]['id'],
                // label: "QoE: " + org_nodes[i]['qoe'].toPrecision(3),
                label: org_nodes[i]['name'] + "\n QoE:" + org_nodes[i]['qoe'].toPrecision(3),
                type: org_nodes[i]['type'],
                image: "/static/" + org_nodes[i]['group'] + "-network.png",
                shape: 'image'
            });
        }

        var edgeNumber = links.length;
        for (var j = 0; j < edgeNumber; j++) {
            edges.push({from: links[j]['source'], to: links[j]['target'], length: EDGE_LENGTH_SUB})
        }

        // create a network
        var container = document.getElementById(divTag);
        var data = {
            nodes: nodes,
            edges: edges
        };
        var options = {
            layout: {
                improvedLayout:true,
                hierarchical: {
                    enabled:false,
                    direction: "RL"
                }
            }
        };
        network = new vis.Network(container, data, options);
        network.on('selectNode', function (params) {
            console.log(params);
            var nodeID = params['nodes'][0];
            console.log(nodeID);
            var node = nodes[nodeID];
            console.log(node);
            var url = "/diag/";
            console.log(url);
            document.location.href=url + "get_network?id=" + node['nodeid'];
        });
    });
}

function drawLatencies(ids, obj_typ, agent_typ, divTag, anomalyTS) {
    // var ids = JSON.parse(("[" + ids_str+ "]"));
    var container = document.getElementById(divTag);
    var url = "http://monitor.cmu-agens.com/get_latency_json?type=" + obj_typ + "&agent=" + agent_typ;
    if (anomalyTS) {
        url = url + "&ts=" + anomalyTS;
    }

    for (var i=0; i<ids.length; i ++) {
        url = url + "&id=" + ids[i];
    }

    console.log(url);

    $.getJSON(url, function (json) {
        var items = json.data;
        var data_type = json.objTyp;
        var unique_groups = [];
        var i;
        for (i = 0; i < items.length; i ++) {
            if (include(unique_groups, items[i].group)){
                continue;
            }
            unique_groups.push(items[i].group);
            items[i].label = items[i].y;
        }

        var groups = new vis.DataSet();
        for (var j = 0; j < unique_groups.length; j ++){
            groups.add({
               id: j,
               content: unique_groups[j]
            });
        }

        console.log(groups);

        var dataset = new vis.DataSet(items);
        var graphHeight;
        if (obj_typ === "link") {
            graphHeight = "600px";
        }
        else {
            graphHeight = "300px";
        }

        var options = {
            start: json.start,
            end: json.end,
            legend: {left:{position:"top-right"}},
            defaultGroup: "",
            dataAxis: {left: {title: {text: "Latency (ms)"}}},
            width: '100%',
            height: graphHeight,
            style: 'line'
        };
        var Graph2d = new vis.Graph2d(container, dataset, groups, options);
    });
}