system_pods = {
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {
    "selfLink": "/api/v1/namespaces/kube-system/pods",
    "resourceVersion": "10092"
  },
  "items": [
    {
      "metadata": {
        "name": "coredns-f9fd979d6-2nflp",
        "generateName": "coredns-f9fd979d6-",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/coredns-f9fd979d6-2nflp",
        "uid": "60a50296-bd2f-432a-be56-54c5b12bda2d",
        "resourceVersion": "6944",
        "creationTimestamp": "2021-07-01T00:37:14Z",
        "labels": {
          "k8s-app": "kube-dns",
          "pod-template-hash": "f9fd979d6"
        },
        "ownerReferences": [
          {
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "name": "coredns-f9fd979d6",
            "uid": "36cd8b07-ad0d-4780-a632-c77cc75420a5",
            "controller": True,
            "blockOwnerDeletion": True
          }
        ],
        "managedFields": [
          {
            "manager": "kube-controller-manager",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-01T00:37:14Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:generateName":{},"f:labels":{".":{},"f:k8s-app":{},"f:pod-template-hash":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"36cd8b07-ad0d-4780-a632-c77cc75420a5\"}":{".":{},"f:apiVersion":{},"f:blockOwnerDeletion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"coredns\"}":{".":{},"f:args":{},"f:image":{},"f:imagePullPolicy":{},"f:livenessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:name":{},"f:ports":{".":{},"k:{\"containerPort\":53,\"protocol\":\"TCP\"}":{".":{},"f:containerPort":{},"f:name":{},"f:protocol":{}},"k:{\"containerPort\":53,\"protocol\":\"UDP\"}":{".":{},"f:containerPort":{},"f:name":{},"f:protocol":{}},"k:{\"containerPort\":9153,\"protocol\":\"TCP\"}":{".":{},"f:containerPort":{},"f:name":{},"f:protocol":{}}},"f:readinessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:resources":{".":{},"f:limits":{".":{},"f:memory":{}},"f:requests":{".":{},"f:cpu":{},"f:memory":{}}},"f:securityContext":{".":{},"f:allowPrivilegeEscalation":{},"f:capabilities":{".":{},"f:add":{},"f:drop":{}},"f:readOnlyRootFilesystem":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/etc/coredns\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:nodeSelector":{".":{},"f:kubernetes.io/os":{}},"f:priorityClassName":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:serviceAccount":{},"f:serviceAccountName":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},"f:volumes":{".":{},"k:{\"name\":\"config-volume\"}":{".":{},"f:configMap":{".":{},"f:defaultMode":{},"f:items":{},"f:name":{}},"f:name":{}}}}}
          },
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:08:14Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"10.1.0.7\"}":{".":{},"f:ip":{}}},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "config-volume",
            "configMap": {
              "name": "coredns",
              "items": [
                {
                  "key": "Corefile",
                  "path": "Corefile"
                }
              ],
              "defaultMode": 420
            }
          },
          {
            "name": "coredns-token-qbm98",
            "secret": {
              "secretName": "coredns-token-qbm98",
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "coredns",
            "image": "k8s.gcr.io/coredns:1.7.0",
            "args": [
              "-conf",
              "/etc/coredns/Corefile"
            ],
            "ports": [
              {
                "name": "dns",
                "containerPort": 53,
                "protocol": "UDP"
              },
              {
                "name": "dns-tcp",
                "containerPort": 53,
                "protocol": "TCP"
              },
              {
                "name": "metrics",
                "containerPort": 9153,
                "protocol": "TCP"
              }
            ],
            "resources": {
              "limits": {
                "memory": "170Mi"
              },
              "requests": {
                "cpu": "100m",
                "memory": "70Mi"
              }
            },
            "volumeMounts": [
              {
                "name": "config-volume",
                "readOnly": True,
                "mountPath": "/etc/coredns"
              },
              {
                "name": "coredns-token-qbm98",
                "readOnly": True,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/health",
                "port": 8080,
                "scheme": "HTTP"
              },
              "initialDelaySeconds": 60,
              "timeoutSeconds": 5,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 5
            },
            "readinessProbe": {
              "httpGet": {
                "path": "/ready",
                "port": 8181,
                "scheme": "HTTP"
              },
              "timeoutSeconds": 1,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 3
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "capabilities": {
                "add": [
                  "NET_BIND_SERVICE"
                ],
                "drop": [
                  "all"
                ]
              },
              "readOnlyRootFilesystem": True,
              "allowPrivilegeEscalation": False
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "Default",
        "nodeSelector": {
          "kubernetes.io/os": "linux"
        },
        "serviceAccountName": "coredns",
        "serviceAccount": "coredns",
        "nodeName": "docker-desktop",
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "key": "CriticalAddonsOnly",
            "operator": "Exists"
          },
          {
            "key": "node-role.kubernetes.io/master",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          }
        ],
        "priorityClassName": "system-cluster-critical",
        "priority": 2000000000,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:14Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:14Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:14Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:14Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "10.1.0.7",
        "podIPs": [
          {
            "ip": "10.1.0.7"
          }
        ],
        "startTime": "2021-07-01T00:37:14Z",
        "containerStatuses": [
          {
            "name": "coredns",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:38Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-01T00:37:17Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://703560db15f0a49b4604cf00cf6402438475232d22dc5663b2701875063a897f"
              }
            },
            "ready": True,
            "restartCount": 1,
            "image": "k8s.gcr.io/coredns:1.7.0",
            "imageID": "docker-pullable://k8s.gcr.io/coredns@sha256:73ca82b4ce829766d4f1f10947c3a338888f876fbed0540dc849c89ff256e90c",
            "containerID": "docker://6cc0b2a7a13778bd263dc8ed9c9a82a4cf6e1bcf77290ff31add43e2b0834085",
            "started": True
          }
        ],
        "qosClass": "Burstable"
      }
    },
    {
      "metadata": {
        "name": "coredns-f9fd979d6-82blw",
        "generateName": "coredns-f9fd979d6-",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/coredns-f9fd979d6-82blw",
        "uid": "4b4212b9-5fb0-4191-858a-e12ade8111a1",
        "resourceVersion": "6935",
        "creationTimestamp": "2021-07-01T00:37:14Z",
        "labels": {
          "k8s-app": "kube-dns",
          "pod-template-hash": "f9fd979d6"
        },
        "ownerReferences": [
          {
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "name": "coredns-f9fd979d6",
            "uid": "36cd8b07-ad0d-4780-a632-c77cc75420a5",
            "controller": True,
            "blockOwnerDeletion": True
          }
        ],
        "managedFields": [
          {
            "manager": "kube-controller-manager",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-01T00:37:14Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:generateName":{},"f:labels":{".":{},"f:k8s-app":{},"f:pod-template-hash":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"36cd8b07-ad0d-4780-a632-c77cc75420a5\"}":{".":{},"f:apiVersion":{},"f:blockOwnerDeletion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"coredns\"}":{".":{},"f:args":{},"f:image":{},"f:imagePullPolicy":{},"f:livenessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:name":{},"f:ports":{".":{},"k:{\"containerPort\":53,\"protocol\":\"TCP\"}":{".":{},"f:containerPort":{},"f:name":{},"f:protocol":{}},"k:{\"containerPort\":53,\"protocol\":\"UDP\"}":{".":{},"f:containerPort":{},"f:name":{},"f:protocol":{}},"k:{\"containerPort\":9153,\"protocol\":\"TCP\"}":{".":{},"f:containerPort":{},"f:name":{},"f:protocol":{}}},"f:readinessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:resources":{".":{},"f:limits":{".":{},"f:memory":{}},"f:requests":{".":{},"f:cpu":{},"f:memory":{}}},"f:securityContext":{".":{},"f:allowPrivilegeEscalation":{},"f:capabilities":{".":{},"f:add":{},"f:drop":{}},"f:readOnlyRootFilesystem":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/etc/coredns\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:nodeSelector":{".":{},"f:kubernetes.io/os":{}},"f:priorityClassName":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:serviceAccount":{},"f:serviceAccountName":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},"f:volumes":{".":{},"k:{\"name\":\"config-volume\"}":{".":{},"f:configMap":{".":{},"f:defaultMode":{},"f:items":{},"f:name":{}},"f:name":{}}}}}
          },
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:08:10Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"10.1.0.6\"}":{".":{},"f:ip":{}}},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "config-volume",
            "configMap": {
              "name": "coredns",
              "items": [
                {
                  "key": "Corefile",
                  "path": "Corefile"
                }
              ],
              "defaultMode": 420
            }
          },
          {
            "name": "coredns-token-qbm98",
            "secret": {
              "secretName": "coredns-token-qbm98",
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "coredns",
            "image": "k8s.gcr.io/coredns:1.7.0",
            "args": [
              "-conf",
              "/etc/coredns/Corefile"
            ],
            "ports": [
              {
                "name": "dns",
                "containerPort": 53,
                "protocol": "UDP"
              },
              {
                "name": "dns-tcp",
                "containerPort": 53,
                "protocol": "TCP"
              },
              {
                "name": "metrics",
                "containerPort": 9153,
                "protocol": "TCP"
              }
            ],
            "resources": {
              "limits": {
                "memory": "170Mi"
              },
              "requests": {
                "cpu": "100m",
                "memory": "70Mi"
              }
            },
            "volumeMounts": [
              {
                "name": "config-volume",
                "readOnly": True,
                "mountPath": "/etc/coredns"
              },
              {
                "name": "coredns-token-qbm98",
                "readOnly": True,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/health",
                "port": 8080,
                "scheme": "HTTP"
              },
              "initialDelaySeconds": 60,
              "timeoutSeconds": 5,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 5
            },
            "readinessProbe": {
              "httpGet": {
                "path": "/ready",
                "port": 8181,
                "scheme": "HTTP"
              },
              "timeoutSeconds": 1,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 3
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "capabilities": {
                "add": [
                  "NET_BIND_SERVICE"
                ],
                "drop": [
                  "all"
                ]
              },
              "readOnlyRootFilesystem": True,
              "allowPrivilegeEscalation": False
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "Default",
        "nodeSelector": {
          "kubernetes.io/os": "linux"
        },
        "serviceAccountName": "coredns",
        "serviceAccount": "coredns",
        "nodeName": "docker-desktop",
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "key": "CriticalAddonsOnly",
            "operator": "Exists"
          },
          {
            "key": "node-role.kubernetes.io/master",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          }
        ],
        "priorityClassName": "system-cluster-critical",
        "priority": 2000000000,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:14Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:10Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:10Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:14Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "10.1.0.6",
        "podIPs": [
          {
            "ip": "10.1.0.6"
          }
        ],
        "startTime": "2021-07-01T00:37:14Z",
        "containerStatuses": [
          {
            "name": "coredns",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:37Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-01T00:37:17Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://9b8921efcd06894aa62a41d46e4d41f66ee94b0c84165028511377f1ccfc58b6"
              }
            },
            "ready": True,
            "restartCount": 1,
            "image": "k8s.gcr.io/coredns:1.7.0",
            "imageID": "docker-pullable://k8s.gcr.io/coredns@sha256:73ca82b4ce829766d4f1f10947c3a338888f876fbed0540dc849c89ff256e90c",
            "containerID": "docker://0ff98e8d0788aa754d47184c3cb15f996490c60ae2acb01e411603901f696680",
            "started": True
          }
        ],
        "qosClass": "Burstable"
      }
    },
    {
      "metadata": {
        "name": "etcd-docker-desktop",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/etcd-docker-desktop",
        "uid": "fc5620a7-39a4-4a14-a1e4-1901706ec171",
        "resourceVersion": "6975",
        "creationTimestamp": "2021-07-01T00:38:19Z",
        "labels": {
          "component": "etcd",
          "tier": "control-plane"
        },
        "annotations": {
          "kubeadm.kubernetes.io/etcd.advertise-client-urls": "https://192.168.65.4:2379",
          "kubernetes.io/config.hash": "127f1e78367a800caa891919cc4b583f",
          "kubernetes.io/config.mirror": "127f1e78367a800caa891919cc4b583f",
          "kubernetes.io/config.seen": "2021-07-01T00:36:51.140054140Z",
          "kubernetes.io/config.source": "file"
        },
        "ownerReferences": [
          {
            "apiVersion": "v1",
            "kind": "Node",
            "name": "docker-desktop",
            "uid": "39323b12-b118-4da2-91e3-d05d4b12d93c",
            "controller": True
          }
        ],
        "managedFields": [
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:08:31Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:annotations":{".":{},"f:kubeadm.kubernetes.io/etcd.advertise-client-urls":{},"f:kubernetes.io/config.hash":{},"f:kubernetes.io/config.mirror":{},"f:kubernetes.io/config.seen":{},"f:kubernetes.io/config.source":{}},"f:labels":{".":{},"f:component":{},"f:tier":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"39323b12-b118-4da2-91e3-d05d4b12d93c\"}":{".":{},"f:apiVersion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"etcd\"}":{".":{},"f:command":{},"f:image":{},"f:imagePullPolicy":{},"f:livenessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:name":{},"f:resources":{},"f:startupProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/run/config/pki/etcd\"}":{".":{},"f:mountPath":{},"f:name":{}},"k:{\"mountPath\":\"/var/lib/etcd\"}":{".":{},"f:mountPath":{},"f:name":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:hostNetwork":{},"f:nodeName":{},"f:priorityClassName":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},"f:volumes":{".":{},"k:{\"name\":\"etcd-certs\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"etcd-data\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}}}},"f:status":{"f:conditions":{".":{},"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"PodScheduled\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"192.168.65.4\"}":{".":{},"f:ip":{}}},"f:qosClass":{},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "etcd-certs",
            "hostPath": {
              "path": "/run/config/pki/etcd",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "etcd-data",
            "hostPath": {
              "path": "/var/lib/etcd",
              "type": "DirectoryOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "etcd",
            "image": "k8s.gcr.io/etcd:3.4.13-0",
            "command": [
              "etcd",
              "--advertise-client-urls=https://192.168.65.4:2379",
              "--cert-file=/run/config/pki/etcd/server.crt",
              "--client-cert-auth=True",
              "--data-dir=/var/lib/etcd",
              "--initial-advertise-peer-urls=https://192.168.65.4:2380",
              "--initial-cluster=docker-desktop=https://192.168.65.4:2380",
              "--key-file=/run/config/pki/etcd/server.key",
              "--listen-client-urls=https://127.0.0.1:2379,https://192.168.65.4:2379",
              "--listen-metrics-urls=http://127.0.0.1:2381",
              "--listen-peer-urls=https://192.168.65.4:2380",
              "--name=docker-desktop",
              "--peer-cert-file=/run/config/pki/etcd/peer.crt",
              "--peer-client-cert-auth=True",
              "--peer-key-file=/run/config/pki/etcd/peer.key",
              "--peer-trusted-ca-file=/run/config/pki/etcd/ca.crt",
              "--snapshot-count=10000",
              "--trusted-ca-file=/run/config/pki/etcd/ca.crt"
            ],
            "resources": {
              
            },
            "volumeMounts": [
              {
                "name": "etcd-data",
                "mountPath": "/var/lib/etcd"
              },
              {
                "name": "etcd-certs",
                "mountPath": "/run/config/pki/etcd"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/health",
                "port": 2381,
                "host": "127.0.0.1",
                "scheme": "HTTP"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "startupProbe": {
              "httpGet": {
                "path": "/health",
                "port": 2381,
                "host": "127.0.0.1",
                "scheme": "HTTP"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 24
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "docker-desktop",
        "hostNetwork": True,
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-node-critical",
        "priority": 2000001000,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:20Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:31Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:31Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:20Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "192.168.65.4",
        "podIPs": [
          {
            "ip": "192.168.65.4"
          }
        ],
        "startTime": "2021-07-10T18:07:20Z",
        "containerStatuses": [
          {
            "name": "etcd",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:21Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-01T00:37:02Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://c49371b3b6bb8f7886c4865ace8b594d5d1b55c537a7774b9c0ec2eb3b6fc93d"
              }
            },
            "ready": True,
            "restartCount": 1,
            "image": "k8s.gcr.io/etcd:3.4.13-0",
            "imageID": "docker-pullable://k8s.gcr.io/etcd@sha256:4ad90a11b55313b182afc186b9876c8e891531b8db4c9bf1541953021618d0e2",
            "containerID": "docker://074195456aba58b1780453b7b16da05ad58e561c0bfe2ca94e4ecf64ae0fb4fb",
            "started": True
          }
        ],
        "qosClass": "BestEffort"
      }
    },
    {
      "metadata": {
        "name": "kube-apiserver-docker-desktop",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-apiserver-docker-desktop",
        "uid": "9d65e258-8c8c-40b0-af6c-eb752bc3db85",
        "resourceVersion": "6844",
        "creationTimestamp": "2021-07-01T00:38:30Z",
        "labels": {
          "component": "kube-apiserver",
          "tier": "control-plane"
        },
        "annotations": {
          "kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint": "192.168.65.4:6443",
          "kubernetes.io/config.hash": "4ac4b5ee26e7058a1ed090c12123e3a6",
          "kubernetes.io/config.mirror": "4ac4b5ee26e7058a1ed090c12123e3a6",
          "kubernetes.io/config.seen": "2021-07-01T00:36:51.140055533Z",
          "kubernetes.io/config.source": "file"
        },
        "ownerReferences": [
          {
            "apiVersion": "v1",
            "kind": "Node",
            "name": "docker-desktop",
            "uid": "39323b12-b118-4da2-91e3-d05d4b12d93c",
            "controller": True
          }
        ],
        "managedFields": [
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:07:33Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:annotations":{".":{},"f:kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint":{},"f:kubernetes.io/config.hash":{},"f:kubernetes.io/config.mirror":{},"f:kubernetes.io/config.seen":{},"f:kubernetes.io/config.source":{}},"f:labels":{".":{},"f:component":{},"f:tier":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"39323b12-b118-4da2-91e3-d05d4b12d93c\"}":{".":{},"f:apiVersion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"kube-apiserver\"}":{".":{},"f:command":{},"f:image":{},"f:imagePullPolicy":{},"f:livenessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:name":{},"f:readinessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:resources":{".":{},"f:requests":{".":{},"f:cpu":{}}},"f:startupProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/etc/ca-certificates\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/etc/ssl/certs\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/run/config/pki\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/usr/local/share/ca-certificates\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/usr/share/ca-certificates\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:hostNetwork":{},"f:nodeName":{},"f:priorityClassName":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},"f:volumes":{".":{},"k:{\"name\":\"ca-certs\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"etc-ca-certificates\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"k8s-certs\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"usr-local-share-ca-certificates\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"usr-share-ca-certificates\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}}}},"f:status":{"f:conditions":{".":{},"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"PodScheduled\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"192.168.65.4\"}":{".":{},"f:ip":{}}},"f:qosClass":{},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "ca-certs",
            "hostPath": {
              "path": "/etc/ssl/certs",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "etc-ca-certificates",
            "hostPath": {
              "path": "/etc/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "k8s-certs",
            "hostPath": {
              "path": "/run/config/pki",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "usr-local-share-ca-certificates",
            "hostPath": {
              "path": "/usr/local/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "usr-share-ca-certificates",
            "hostPath": {
              "path": "/usr/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "kube-apiserver",
            "image": "k8s.gcr.io/kube-apiserver:v1.19.7",
            "command": [
              "kube-apiserver",
              "--advertise-address=192.168.65.4",
              "--allow-privileged=True",
              "--authorization-mode=Node,RBAC",
              "--client-ca-file=/run/config/pki/ca.crt",
              "--enable-admission-plugins=NodeRestriction",
              "--enable-bootstrap-token-auth=True",
              "--etcd-cafile=/run/config/pki/etcd/ca.crt",
              "--etcd-certfile=/run/config/pki/apiserver-etcd-client.crt",
              "--etcd-keyfile=/run/config/pki/apiserver-etcd-client.key",
              "--etcd-servers=https://127.0.0.1:2379",
              "--insecure-port=0",
              "--kubelet-client-certificate=/run/config/pki/apiserver-kubelet-client.crt",
              "--kubelet-client-key=/run/config/pki/apiserver-kubelet-client.key",
              "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
              "--proxy-client-cert-file=/run/config/pki/front-proxy-client.crt",
              "--proxy-client-key-file=/run/config/pki/front-proxy-client.key",
              "--requestheader-allowed-names=front-proxy-client",
              "--requestheader-client-ca-file=/run/config/pki/front-proxy-ca.crt",
              "--requestheader-extra-headers-prefix=X-Remote-Extra-",
              "--requestheader-group-headers=X-Remote-Group",
              "--requestheader-username-headers=X-Remote-User",
              "--secure-port=6443",
              "--service-account-key-file=/run/config/pki/sa.pub",
              "--service-cluster-ip-range=10.96.0.0/12",
              "--tls-cert-file=/run/config/pki/apiserver.crt",
              "--tls-private-key-file=/run/config/pki/apiserver.key",
              "--watch-cache=False"
            ],
            "resources": {
              "requests": {
                "cpu": "250m"
              }
            },
            "volumeMounts": [
              {
                "name": "ca-certs",
                "readOnly": True,
                "mountPath": "/etc/ssl/certs"
              },
              {
                "name": "etc-ca-certificates",
                "readOnly": True,
                "mountPath": "/etc/ca-certificates"
              },
              {
                "name": "k8s-certs",
                "readOnly": True,
                "mountPath": "/run/config/pki"
              },
              {
                "name": "usr-local-share-ca-certificates",
                "readOnly": True,
                "mountPath": "/usr/local/share/ca-certificates"
              },
              {
                "name": "usr-share-ca-certificates",
                "readOnly": True,
                "mountPath": "/usr/share/ca-certificates"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/livez",
                "port": 6443,
                "host": "192.168.65.4",
                "scheme": "HTTPS"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "readinessProbe": {
              "httpGet": {
                "path": "/readyz",
                "port": 6443,
                "host": "192.168.65.4",
                "scheme": "HTTPS"
              },
              "timeoutSeconds": 15,
              "periodSeconds": 1,
              "successThreshold": 1,
              "failureThreshold": 3
            },
            "startupProbe": {
              "httpGet": {
                "path": "/livez",
                "port": 6443,
                "host": "192.168.65.4",
                "scheme": "HTTPS"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 24
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "docker-desktop",
        "hostNetwork": True,
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-node-critical",
        "priority": 2000001000,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:01Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:31Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:31Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:01Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "192.168.65.4",
        "podIPs": [
          {
            "ip": "192.168.65.4"
          }
        ],
        "startTime": "2021-07-01T00:37:01Z",
        "containerStatuses": [
          {
            "name": "kube-apiserver",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:21Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-01T00:37:02Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://c91e305dab3e6ad306c77c1a0b25a08d9885c24aa762289e63a0724af66cc138"
              }
            },
            "ready": True,
            "restartCount": 1,
            "image": "k8s.gcr.io/kube-apiserver:v1.19.7",
            "imageID": "docker-pullable://k8s.gcr.io/kube-apiserver@sha256:b964f0fa81209c3290aa74573009313701403521eafcdccb3b332adaf4f22f7e",
            "containerID": "docker://726b471756ccd4942fb08f1400439c093b8f7271671dd3bc93d5de9a9e8e7920",
            "started": True
          }
        ],
        "qosClass": "Burstable"
      }
    },
    {
      "metadata": {
        "name": "kube-controller-manager-docker-desktop",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-controller-manager-docker-desktop",
        "uid": "63a8abcd-3b9a-45d4-8f8d-c4191ab01a49",
        "resourceVersion": "6980",
        "creationTimestamp": "2021-07-01T00:38:16Z",
        "labels": {
          "component": "kube-controller-manager",
          "tier": "control-plane"
        },
        "annotations": {
          "kubernetes.io/config.hash": "77e9d7fdbb29bf4b5600ab5fbb368a2b",
          "kubernetes.io/config.mirror": "77e9d7fdbb29bf4b5600ab5fbb368a2b",
          "kubernetes.io/config.seen": "2021-07-01T00:36:51.140056746Z",
          "kubernetes.io/config.source": "file"
        },
        "ownerReferences": [
          {
            "apiVersion": "v1",
            "kind": "Node",
            "name": "docker-desktop",
            "uid": "39323b12-b118-4da2-91e3-d05d4b12d93c",
            "controller": True
          }
        ],
        "managedFields": [
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:08:34Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:annotations":{".":{},"f:kubernetes.io/config.hash":{},"f:kubernetes.io/config.mirror":{},"f:kubernetes.io/config.seen":{},"f:kubernetes.io/config.source":{}},"f:labels":{".":{},"f:component":{},"f:tier":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"39323b12-b118-4da2-91e3-d05d4b12d93c\"}":{".":{},"f:apiVersion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"kube-controller-manager\"}":{".":{},"f:command":{},"f:image":{},"f:imagePullPolicy":{},"f:livenessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:name":{},"f:resources":{".":{},"f:requests":{".":{},"f:cpu":{}}},"f:startupProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/etc/ca-certificates\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/etc/kubernetes/controller-manager.conf\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/etc/ssl/certs\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/run/config/pki\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/usr/libexec/kubernetes/kubelet-plugins/volume/exec\"}":{".":{},"f:mountPath":{},"f:name":{}},"k:{\"mountPath\":\"/usr/local/share/ca-certificates\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/usr/share/ca-certificates\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:hostNetwork":{},"f:nodeName":{},"f:priorityClassName":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},"f:volumes":{".":{},"k:{\"name\":\"ca-certs\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"etc-ca-certificates\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"flexvolume-dir\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"k8s-certs\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"kubeconfig\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"usr-local-share-ca-certificates\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"usr-share-ca-certificates\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}}}},"f:status":{"f:conditions":{".":{},"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"PodScheduled\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"192.168.65.4\"}":{".":{},"f:ip":{}}},"f:qosClass":{},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "ca-certs",
            "hostPath": {
              "path": "/etc/ssl/certs",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "etc-ca-certificates",
            "hostPath": {
              "path": "/etc/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "flexvolume-dir",
            "hostPath": {
              "path": "/usr/libexec/kubernetes/kubelet-plugins/volume/exec",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "k8s-certs",
            "hostPath": {
              "path": "/run/config/pki",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "kubeconfig",
            "hostPath": {
              "path": "/etc/kubernetes/controller-manager.conf",
              "type": "FileOrCreate"
            }
          },
          {
            "name": "usr-local-share-ca-certificates",
            "hostPath": {
              "path": "/usr/local/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "usr-share-ca-certificates",
            "hostPath": {
              "path": "/usr/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "kube-controller-manager",
            "image": "k8s.gcr.io/kube-controller-manager:v1.19.7",
            "command": [
              "kube-controller-manager",
              "--authentication-kubeconfig=/etc/kubernetes/controller-manager.conf",
              "--authorization-kubeconfig=/etc/kubernetes/controller-manager.conf",
              "--bind-address=127.0.0.1",
              "--client-ca-file=/run/config/pki/ca.crt",
              "--cluster-name=kubernetes",
              "--cluster-signing-cert-file=/run/config/pki/ca.crt",
              "--cluster-signing-key-file=/run/config/pki/ca.key",
              "--controllers=*,bootstrapsigner,tokencleaner",
              "--horizontal-pod-autoscaler-sync-period=60s",
              "--kubeconfig=/etc/kubernetes/controller-manager.conf",
              "--leader-elect=False",
              "--node-monitor-grace-period=180s",
              "--node-monitor-period=30s",
              "--port=0",
              "--pvclaimbinder-sync-period=60s",
              "--requestheader-client-ca-file=/run/config/pki/front-proxy-ca.crt",
              "--root-ca-file=/run/config/pki/ca.crt",
              "--service-account-private-key-file=/run/config/pki/sa.key",
              "--use-service-account-credentials=True"
            ],
            "resources": {
              "requests": {
                "cpu": "200m"
              }
            },
            "volumeMounts": [
              {
                "name": "ca-certs",
                "readOnly": True,
                "mountPath": "/etc/ssl/certs"
              },
              {
                "name": "etc-ca-certificates",
                "readOnly": True,
                "mountPath": "/etc/ca-certificates"
              },
              {
                "name": "flexvolume-dir",
                "mountPath": "/usr/libexec/kubernetes/kubelet-plugins/volume/exec"
              },
              {
                "name": "k8s-certs",
                "readOnly": True,
                "mountPath": "/run/config/pki"
              },
              {
                "name": "kubeconfig",
                "readOnly": True,
                "mountPath": "/etc/kubernetes/controller-manager.conf"
              },
              {
                "name": "usr-local-share-ca-certificates",
                "readOnly": True,
                "mountPath": "/usr/local/share/ca-certificates"
              },
              {
                "name": "usr-share-ca-certificates",
                "readOnly": True,
                "mountPath": "/usr/share/ca-certificates"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/healthz",
                "port": 10257,
                "host": "127.0.0.1",
                "scheme": "HTTPS"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "startupProbe": {
              "httpGet": {
                "path": "/healthz",
                "port": 10257,
                "host": "127.0.0.1",
                "scheme": "HTTPS"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 24
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "docker-desktop",
        "hostNetwork": True,
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-node-critical",
        "priority": 2000001000,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:20Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:34Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:34Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:20Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "192.168.65.4",
        "podIPs": [
          {
            "ip": "192.168.65.4"
          }
        ],
        "startTime": "2021-07-10T18:07:20Z",
        "containerStatuses": [
          {
            "name": "kube-controller-manager",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:21Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-01T00:37:02Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://5470f504d4f8e1f58a6df6fbe81f160d64620fad0937abb5f44e42ef4587b239"
              }
            },
            "ready": True,
            "restartCount": 1,
            "image": "k8s.gcr.io/kube-controller-manager:v1.19.7",
            "imageID": "docker-pullable://k8s.gcr.io/kube-controller-manager@sha256:6a11b3700ad7af2f5772451689c68fa963118fba8c106b46f539bd0b44daba30",
            "containerID": "docker://cba1dc7f9be990b5f79e37f45c6cd6d03019720877687e4fab6e547f62ee4363",
            "started": True
          }
        ],
        "qosClass": "Burstable"
      }
    },
    {
      "metadata": {
        "name": "kube-proxy-xhlsd",
        "generateName": "kube-proxy-",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-proxy-xhlsd",
        "uid": "10b5c7cf-2164-41a8-8f48-eb7670876856",
        "resourceVersion": "6820",
        "creationTimestamp": "2021-07-01T00:37:14Z",
        "labels": {
          "controller-revision-hash": "8cb89d659",
          "k8s-app": "kube-proxy",
          "pod-template-generation": "1"
        },
        "ownerReferences": [
          {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "name": "kube-proxy",
            "uid": "665008f1-6eab-4d6d-8281-f82f80f69ca8",
            "controller": True,
            "blockOwnerDeletion": True
          }
        ],
        "managedFields": [
          {
            "manager": "kube-controller-manager",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-01T00:37:14Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:generateName":{},"f:labels":{".":{},"f:controller-revision-hash":{},"f:k8s-app":{},"f:pod-template-generation":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"665008f1-6eab-4d6d-8281-f82f80f69ca8\"}":{".":{},"f:apiVersion":{},"f:blockOwnerDeletion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:affinity":{".":{},"f:nodeAffinity":{".":{},"f:requiredDuringSchedulingIgnoredDuringExecution":{".":{},"f:nodeSelectorTerms":{}}}},"f:containers":{"k:{\"name\":\"kube-proxy\"}":{".":{},"f:command":{},"f:env":{".":{},"k:{\"name\":\"NODE_NAME\"}":{".":{},"f:name":{},"f:valueFrom":{".":{},"f:fieldRef":{".":{},"f:apiVersion":{},"f:fieldPath":{}}}}},"f:image":{},"f:imagePullPolicy":{},"f:name":{},"f:resources":{},"f:securityContext":{".":{},"f:privileged":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/lib/modules\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/run/xtables.lock\"}":{".":{},"f:mountPath":{},"f:name":{}},"k:{\"mountPath\":\"/var/lib/kube-proxy\"}":{".":{},"f:mountPath":{},"f:name":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:hostNetwork":{},"f:nodeSelector":{".":{},"f:kubernetes.io/os":{}},"f:priorityClassName":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:serviceAccount":{},"f:serviceAccountName":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},"f:volumes":{".":{},"k:{\"name\":\"kube-proxy\"}":{".":{},"f:configMap":{".":{},"f:defaultMode":{},"f:name":{}},"f:name":{}},"k:{\"name\":\"lib-modules\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}},"k:{\"name\":\"xtables-lock\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}}}}}
          },
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:07:30Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"192.168.65.4\"}":{".":{},"f:ip":{}}},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "kube-proxy",
            "configMap": {
              "name": "kube-proxy",
              "defaultMode": 420
            }
          },
          {
            "name": "xtables-lock",
            "hostPath": {
              "path": "/run/xtables.lock",
              "type": "FileOrCreate"
            }
          },
          {
            "name": "lib-modules",
            "hostPath": {
              "path": "/lib/modules",
              "type": ""
            }
          },
          {
            "name": "kube-proxy-token-wgzc6",
            "secret": {
              "secretName": "kube-proxy-token-wgzc6",
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "kube-proxy",
            "image": "k8s.gcr.io/kube-proxy:v1.19.7",
            "command": [
              "/usr/local/bin/kube-proxy",
              "--config=/var/lib/kube-proxy/config.conf",
              "--hostname-override=$(NODE_NAME)"
            ],
            "env": [
              {
                "name": "NODE_NAME",
                "valueFrom": {
                  "fieldRef": {
                    "apiVersion": "v1",
                    "fieldPath": "spec.nodeName"
                  }
                }
              }
            ],
            "resources": {
              
            },
            "volumeMounts": [
              {
                "name": "kube-proxy",
                "mountPath": "/var/lib/kube-proxy"
              },
              {
                "name": "xtables-lock",
                "mountPath": "/run/xtables.lock"
              },
              {
                "name": "lib-modules",
                "readOnly": True,
                "mountPath": "/lib/modules"
              },
              {
                "name": "kube-proxy-token-wgzc6",
                "readOnly": True,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "privileged": True
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeSelector": {
          "kubernetes.io/os": "linux"
        },
        "serviceAccountName": "kube-proxy",
        "serviceAccount": "kube-proxy",
        "nodeName": "docker-desktop",
        "hostNetwork": True,
        "securityContext": {
          
        },
        "affinity": {
          "nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
              "nodeSelectorTerms": [
                {
                  "matchFields": [
                    {
                      "key": "metadata.name",
                      "operator": "In",
                      "values": [
                        "docker-desktop"
                      ]
                    }
                  ]
                }
              ]
            }
          }
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "key": "CriticalAddonsOnly",
            "operator": "Exists"
          },
          {
            "operator": "Exists"
          },
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute"
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute"
          },
          {
            "key": "node.kubernetes.io/disk-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/memory-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/pid-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/unschedulable",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/network-unavailable",
            "operator": "Exists",
            "effect": "NoSchedule"
          }
        ],
        "priorityClassName": "system-node-critical",
        "priority": 2000001000,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:14Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:29Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:29Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:14Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "192.168.65.4",
        "podIPs": [
          {
            "ip": "192.168.65.4"
          }
        ],
        "startTime": "2021-07-01T00:37:14Z",
        "containerStatuses": [
          {
            "name": "kube-proxy",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:29Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-01T00:37:16Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://c5e1c878cc5cf876fa5da068f14cea9534aca927a5d9808f2c105aea80bd7dd9"
              }
            },
            "ready": True,
            "restartCount": 1,
            "image": "k8s.gcr.io/kube-proxy:v1.19.7",
            "imageID": "docker-pullable://k8s.gcr.io/kube-proxy@sha256:d1217333dd1f1c76da0a9dbe85aef481c0fde0643a900c3f7113caf3fe4db1d7",
            "containerID": "docker://863fd8b31ae34193a48a0413dcdbae96de5ffe1db3f112429478bd85f9962d13",
            "started": True
          }
        ],
        "qosClass": "BestEffort"
      }
    },
    {
      "metadata": {
        "name": "kube-scheduler-docker-desktop",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-scheduler-docker-desktop",
        "uid": "5e3aa74f-9bea-43fb-a8db-2069a5092a30",
        "resourceVersion": "6999",
        "creationTimestamp": "2021-07-01T00:38:15Z",
        "labels": {
          "component": "kube-scheduler",
          "tier": "control-plane"
        },
        "annotations": {
          "kubernetes.io/config.hash": "57b58b3eb5589cb745c50233392349fb",
          "kubernetes.io/config.mirror": "57b58b3eb5589cb745c50233392349fb",
          "kubernetes.io/config.seen": "2021-07-01T00:36:51.140049340Z",
          "kubernetes.io/config.source": "file"
        },
        "ownerReferences": [
          {
            "apiVersion": "v1",
            "kind": "Node",
            "name": "docker-desktop",
            "uid": "39323b12-b118-4da2-91e3-d05d4b12d93c",
            "controller": True
          }
        ],
        "managedFields": [
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:08:46Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:annotations":{".":{},"f:kubernetes.io/config.hash":{},"f:kubernetes.io/config.mirror":{},"f:kubernetes.io/config.seen":{},"f:kubernetes.io/config.source":{}},"f:labels":{".":{},"f:component":{},"f:tier":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"39323b12-b118-4da2-91e3-d05d4b12d93c\"}":{".":{},"f:apiVersion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:spec":{"f:containers":{"k:{\"name\":\"kube-scheduler\"}":{".":{},"f:command":{},"f:image":{},"f:imagePullPolicy":{},"f:livenessProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:name":{},"f:resources":{".":{},"f:requests":{".":{},"f:cpu":{}}},"f:startupProbe":{".":{},"f:failureThreshold":{},"f:httpGet":{".":{},"f:host":{},"f:path":{},"f:port":{},"f:scheme":{}},"f:initialDelaySeconds":{},"f:periodSeconds":{},"f:successThreshold":{},"f:timeoutSeconds":{}},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/etc/kubernetes/scheduler.conf\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:hostNetwork":{},"f:nodeName":{},"f:priorityClassName":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},"f:volumes":{".":{},"k:{\"name\":\"kubeconfig\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}}}},"f:status":{"f:conditions":{".":{},"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"PodScheduled\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"192.168.65.4\"}":{".":{},"f:ip":{}}},"f:qosClass":{},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "kubeconfig",
            "hostPath": {
              "path": "/etc/kubernetes/scheduler.conf",
              "type": "FileOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "kube-scheduler",
            "image": "k8s.gcr.io/kube-scheduler:v1.19.7",
            "command": [
              "kube-scheduler",
              "--authentication-kubeconfig=/etc/kubernetes/scheduler.conf",
              "--authorization-kubeconfig=/etc/kubernetes/scheduler.conf",
              "--bind-address=127.0.0.1",
              "--kubeconfig=/etc/kubernetes/scheduler.conf",
              "--leader-elect=True",
              "--port=0"
            ],
            "resources": {
              "requests": {
                "cpu": "100m"
              }
            },
            "volumeMounts": [
              {
                "name": "kubeconfig",
                "readOnly": True,
                "mountPath": "/etc/kubernetes/scheduler.conf"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/healthz",
                "port": 10259,
                "host": "127.0.0.1",
                "scheme": "HTTPS"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "startupProbe": {
              "httpGet": {
                "path": "/healthz",
                "port": 10259,
                "host": "127.0.0.1",
                "scheme": "HTTPS"
              },
              "initialDelaySeconds": 10,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 24
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "docker-desktop",
        "hostNetwork": True,
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-node-critical",
        "priority": 2000001000,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:20Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:46Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:46Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:20Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "192.168.65.4",
        "podIPs": [
          {
            "ip": "192.168.65.4"
          }
        ],
        "startTime": "2021-07-10T18:07:20Z",
        "containerStatuses": [
          {
            "name": "kube-scheduler",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:21Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-10T17:43:38Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://8000ae5b85c1f8758436639aad73c295ed7f677cb9cfdf79603f4d707f1dc6dd"
              }
            },
            "ready": True,
            "restartCount": 4,
            "image": "k8s.gcr.io/kube-scheduler:v1.19.7",
            "imageID": "docker-pullable://k8s.gcr.io/kube-scheduler@sha256:0104e0a2954fdc467424a450a0362531b2081f809586446e4b2e63efb376a89a",
            "containerID": "docker://e9d989de5ba50d563d4a116016ed5d0cc2798024aa1841c72c305b1b615850c1",
            "started": True
          }
        ],
        "qosClass": "Burstable"
      }
    },
    {
      "metadata": {
        "name": "storage-provisioner",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/storage-provisioner",
        "uid": "2d7d6a67-d7ad-4b59-a1a1-149c1091eeaa",
        "resourceVersion": "6965",
        "creationTimestamp": "2021-07-01T00:37:22Z",
        "labels": {
          "component": "storage-provisioner"
        },
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"component\":\"storage-provisioner\"},\"name\":\"storage-provisioner\",\"namespace\":\"kube-system\"},\"spec\":{\"containers\":[{\"args\":[\"/var/lib/k8s-pvs\"],\"image\":\"docker/desktop-storage-provisioner:v1.1\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"storage-provisioner\",\"volumeMounts\":[{\"mountPath\":\"/var/lib/k8s-pvs\",\"name\":\"pvs\"}]}],\"serviceAccountName\":\"storage-provisioner\",\"volumes\":[{\"hostPath\":{\"path\":\"/var/lib/k8s-pvs\",\"type\":\"Directory\"},\"name\":\"pvs\"}]}}\n"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-01T00:37:22Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}},"f:labels":{".":{},"f:component":{}}},"f:spec":{"f:containers":{"k:{\"name\":\"storage-provisioner\"}":{".":{},"f:args":{},"f:image":{},"f:imagePullPolicy":{},"f:name":{},"f:resources":{},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/var/lib/k8s-pvs\"}":{".":{},"f:mountPath":{},"f:name":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:serviceAccount":{},"f:serviceAccountName":{},"f:terminationGracePeriodSeconds":{},"f:volumes":{".":{},"k:{\"name\":\"pvs\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}}}}}
          },
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:08:24Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"10.1.0.9\"}":{".":{},"f:ip":{}}},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "pvs",
            "hostPath": {
              "path": "/var/lib/k8s-pvs",
              "type": "Directory"
            }
          },
          {
            "name": "storage-provisioner-token-pdddb",
            "secret": {
              "secretName": "storage-provisioner-token-pdddb",
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "storage-provisioner",
            "image": "docker/desktop-storage-provisioner:v1.1",
            "args": [
              "/var/lib/k8s-pvs"
            ],
            "resources": {
              
            },
            "volumeMounts": [
              {
                "name": "pvs",
                "mountPath": "/var/lib/k8s-pvs"
              },
              {
                "name": "storage-provisioner-token-pdddb",
                "readOnly": True,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "storage-provisioner",
        "serviceAccount": "storage-provisioner",
        "nodeName": "docker-desktop",
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          }
        ],
        "priority": 0,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:22Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:24Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:08:24Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:22Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "10.1.0.9",
        "podIPs": [
          {
            "ip": "10.1.0.9"
          }
        ],
        "startTime": "2021-07-01T00:37:22Z",
        "containerStatuses": [
          {
            "name": "storage-provisioner",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:08:23Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 1,
                "reason": "Error",
                "startedAt": "2021-07-10T18:07:38Z",
                "finishedAt": "2021-07-10T18:08:08Z",
                "containerID": "docker://4d3dc7b0587c4a5f8eac2fb59a736f968a4241c7f007c04adda093c814fcc097"
              }
            },
            "ready": True,
            "restartCount": 4,
            "image": "docker/desktop-storage-provisioner:v1.1",
            "imageID": "docker-pullable://docker/desktop-storage-provisioner@sha256:b39d74c0eb50b82375f916ff2bf0d10cccff09015e01c55eaa123ec6549c4177",
            "containerID": "docker://eb6cee25dd5661ee49ced85e8f8248a746a5f79cd66796e27e1d608f55ad5d94",
            "started": True
          }
        ],
        "qosClass": "BestEffort"
      }
    },
    {
      "metadata": {
        "name": "vpnkit-controller",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/vpnkit-controller",
        "uid": "54e852d7-2fa4-46a6-b749-ff27128b246b",
        "resourceVersion": "6879",
        "creationTimestamp": "2021-07-01T00:37:22Z",
        "labels": {
          "component": "vpnkit-controller"
        },
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"component\":\"vpnkit-controller\"},\"name\":\"vpnkit-controller\",\"namespace\":\"kube-system\"},\"spec\":{\"containers\":[{\"command\":[\"/kube-vpnkit-forwarder\",\"-path\",\"/run/host-services/backend.sock\"],\"image\":\"docker/desktop-vpnkit-controller:v1.0\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"vpnkit-controller\",\"volumeMounts\":[{\"mountPath\":\"/run/host-services/backend.sock\",\"name\":\"api\"}]}],\"serviceAccountName\":\"vpnkit-controller\",\"volumes\":[{\"hostPath\":{\"path\":\"/run/host-services/backend.sock\"},\"name\":\"api\"}]}}\n"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-01T00:37:22Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}},"f:labels":{".":{},"f:component":{}}},"f:spec":{"f:containers":{"k:{\"name\":\"vpnkit-controller\"}":{".":{},"f:command":{},"f:image":{},"f:imagePullPolicy":{},"f:name":{},"f:resources":{},"f:terminationMessagePath":{},"f:terminationMessagePolicy":{},"f:volumeMounts":{".":{},"k:{\"mountPath\":\"/run/host-services/backend.sock\"}":{".":{},"f:mountPath":{},"f:name":{}}}}},"f:dnsPolicy":{},"f:enableServiceLinks":{},"f:restartPolicy":{},"f:schedulerName":{},"f:securityContext":{},"f:serviceAccount":{},"f:serviceAccountName":{},"f:terminationGracePeriodSeconds":{},"f:volumes":{".":{},"k:{\"name\":\"api\"}":{".":{},"f:hostPath":{".":{},"f:path":{},"f:type":{}},"f:name":{}}}}}
          },
          {
            "manager": "kubelet",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-10T18:07:38Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"f:status":{"f:conditions":{"k:{\"type\":\"ContainersReady\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Initialized\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}},"k:{\"type\":\"Ready\"}":{".":{},"f:lastProbeTime":{},"f:lastTransitionTime":{},"f:status":{},"f:type":{}}},"f:containerStatuses":{},"f:hostIP":{},"f:phase":{},"f:podIP":{},"f:podIPs":{".":{},"k:{\"ip\":\"10.1.0.8\"}":{".":{},"f:ip":{}}},"f:startTime":{}}}
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "api",
            "hostPath": {
              "path": "/run/host-services/backend.sock",
              "type": ""
            }
          },
          {
            "name": "vpnkit-controller-token-9vhf7",
            "secret": {
              "secretName": "vpnkit-controller-token-9vhf7",
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "vpnkit-controller",
            "image": "docker/desktop-vpnkit-controller:v1.0",
            "command": [
              "/kube-vpnkit-forwarder",
              "-path",
              "/run/host-services/backend.sock"
            ],
            "resources": {
              
            },
            "volumeMounts": [
              {
                "name": "api",
                "mountPath": "/run/host-services/backend.sock"
              },
              {
                "name": "vpnkit-controller-token-9vhf7",
                "readOnly": True,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "vpnkit-controller",
        "serviceAccount": "vpnkit-controller",
        "nodeName": "docker-desktop",
        "securityContext": {
          
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          }
        ],
        "priority": 0,
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:22Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:38Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-10T18:07:38Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": None,
            "lastTransitionTime": "2021-07-01T00:37:22Z"
          }
        ],
        "hostIP": "192.168.65.4",
        "podIP": "10.1.0.8",
        "podIPs": [
          {
            "ip": "10.1.0.8"
          }
        ],
        "startTime": "2021-07-01T00:37:22Z",
        "containerStatuses": [
          {
            "name": "vpnkit-controller",
            "state": {
              "running": {
                "startedAt": "2021-07-10T18:07:38Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2021-07-01T00:37:33Z",
                "finishedAt": "2021-07-10T18:06:49Z",
                "containerID": "docker://41d0eee3fe76e9761c37d1e12c268903f6ae943ee1fec3b033d6cfaff0be5614"
              }
            },
            "ready": True,
            "restartCount": 1,
            "image": "docker/desktop-vpnkit-controller:v1.0",
            "imageID": "docker-pullable://docker/desktop-vpnkit-controller@sha256:6800d69751e483710a0949fbd01c459934a18ede9d227166def0af44f3a46970",
            "containerID": "docker://842880b219a14c2574e31223650b510a1a80b36edd0ec8e09797302997fc274a",
            "started": True
          }
        ],
        "qosClass": "BestEffort"
      }
    }
  ]
}