// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Sch.outputs.GetServiceConnectorTargetDimension;
import com.pulumi.oci.Sch.outputs.GetServiceConnectorTargetPrivateEndpointMetadata;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetServiceConnectorTarget {
    /**
     * @return The batch rollover size in megabytes.
     * 
     */
    private Integer batchRolloverSizeInMbs;
    /**
     * @return The batch rollover time in milliseconds.
     * 
     */
    private Integer batchRolloverTimeInMs;
    /**
     * @return Size limit (kilobytes) for batch sent to invoke the function.
     * 
     */
    private Integer batchSizeInKbs;
    /**
     * @return The batch rollover size in number of messages. Only one size option can be specified: `batchSizeInKbs` or `batchSizeInNum`.
     * 
     */
    private Integer batchSizeInNum;
    /**
     * @return Time limit (seconds) for batch sent to invoke the function.
     * 
     */
    private Integer batchTimeInSec;
    /**
     * @return The name of the bucket. Valid characters are letters (upper or lower case), numbers, hyphens (-), underscores(_), and periods (.). Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. Example: my-new-bucket1
     * 
     */
    private String bucket;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
     * 
     */
    private String compartmentId;
    /**
     * @return List of dimension names and values.
     * 
     */
    private List<GetServiceConnectorTargetDimension> dimensions;
    /**
     * @return Whether to apply a simplified, user-friendly format to the message. Applies only when friendly formatting is supported by the connector source and the subscription protocol. Example: `true`
     * 
     */
    private Boolean enableFormattedMessaging;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the function to be used as a task.
     * 
     */
    private String functionId;
    /**
     * @return The type of dimension value: static or evaluated.
     * 
     */
    private String kind;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Logging Analytics log group.
     * 
     */
    private String logGroupId;
    /**
     * @return Identifier of the log source that you want to use for processing data received from the connector source. Applies to `StreamingSource` only. Equivalent to `name` at [LogAnalyticsSource](https://docs.cloud.oracle.com/iaas/api/#/en/logan-api-spec/latest/LogAnalyticsSource/).
     * 
     */
    private String logSourceIdentifier;
    /**
     * @return The name of the metric. Example: `CpuUtilization`
     * 
     */
    private String metric;
    /**
     * @return The namespace of the metric. Example: `oci_computeagent`
     * 
     */
    private String metricNamespace;
    /**
     * @return The namespace.
     * 
     */
    private String namespace;
    /**
     * @return The prefix of the objects. Avoid entering confidential information.
     * 
     */
    private String objectNamePrefix;
    /**
     * @return The private endpoint metadata for the connector&#39;s source or target.
     * 
     */
    private List<GetServiceConnectorTargetPrivateEndpointMetadata> privateEndpointMetadatas;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
     * 
     */
    private String streamId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic.
     * 
     */
    private String topicId;

    private GetServiceConnectorTarget() {}
    /**
     * @return The batch rollover size in megabytes.
     * 
     */
    public Integer batchRolloverSizeInMbs() {
        return this.batchRolloverSizeInMbs;
    }
    /**
     * @return The batch rollover time in milliseconds.
     * 
     */
    public Integer batchRolloverTimeInMs() {
        return this.batchRolloverTimeInMs;
    }
    /**
     * @return Size limit (kilobytes) for batch sent to invoke the function.
     * 
     */
    public Integer batchSizeInKbs() {
        return this.batchSizeInKbs;
    }
    /**
     * @return The batch rollover size in number of messages. Only one size option can be specified: `batchSizeInKbs` or `batchSizeInNum`.
     * 
     */
    public Integer batchSizeInNum() {
        return this.batchSizeInNum;
    }
    /**
     * @return Time limit (seconds) for batch sent to invoke the function.
     * 
     */
    public Integer batchTimeInSec() {
        return this.batchTimeInSec;
    }
    /**
     * @return The name of the bucket. Valid characters are letters (upper or lower case), numbers, hyphens (-), underscores(_), and periods (.). Bucket names must be unique within an Object Storage namespace. Avoid entering confidential information. Example: my-new-bucket1
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return List of dimension names and values.
     * 
     */
    public List<GetServiceConnectorTargetDimension> dimensions() {
        return this.dimensions;
    }
    /**
     * @return Whether to apply a simplified, user-friendly format to the message. Applies only when friendly formatting is supported by the connector source and the subscription protocol. Example: `true`
     * 
     */
    public Boolean enableFormattedMessaging() {
        return this.enableFormattedMessaging;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the function to be used as a task.
     * 
     */
    public String functionId() {
        return this.functionId;
    }
    /**
     * @return The type of dimension value: static or evaluated.
     * 
     */
    public String kind() {
        return this.kind;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Logging Analytics log group.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return Identifier of the log source that you want to use for processing data received from the connector source. Applies to `StreamingSource` only. Equivalent to `name` at [LogAnalyticsSource](https://docs.cloud.oracle.com/iaas/api/#/en/logan-api-spec/latest/LogAnalyticsSource/).
     * 
     */
    public String logSourceIdentifier() {
        return this.logSourceIdentifier;
    }
    /**
     * @return The name of the metric. Example: `CpuUtilization`
     * 
     */
    public String metric() {
        return this.metric;
    }
    /**
     * @return The namespace of the metric. Example: `oci_computeagent`
     * 
     */
    public String metricNamespace() {
        return this.metricNamespace;
    }
    /**
     * @return The namespace.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The prefix of the objects. Avoid entering confidential information.
     * 
     */
    public String objectNamePrefix() {
        return this.objectNamePrefix;
    }
    /**
     * @return The private endpoint metadata for the connector&#39;s source or target.
     * 
     */
    public List<GetServiceConnectorTargetPrivateEndpointMetadata> privateEndpointMetadatas() {
        return this.privateEndpointMetadatas;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
     * 
     */
    public String streamId() {
        return this.streamId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic.
     * 
     */
    public String topicId() {
        return this.topicId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceConnectorTarget defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer batchRolloverSizeInMbs;
        private Integer batchRolloverTimeInMs;
        private Integer batchSizeInKbs;
        private Integer batchSizeInNum;
        private Integer batchTimeInSec;
        private String bucket;
        private String compartmentId;
        private List<GetServiceConnectorTargetDimension> dimensions;
        private Boolean enableFormattedMessaging;
        private String functionId;
        private String kind;
        private String logGroupId;
        private String logSourceIdentifier;
        private String metric;
        private String metricNamespace;
        private String namespace;
        private String objectNamePrefix;
        private List<GetServiceConnectorTargetPrivateEndpointMetadata> privateEndpointMetadatas;
        private String streamId;
        private String topicId;
        public Builder() {}
        public Builder(GetServiceConnectorTarget defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.batchRolloverSizeInMbs = defaults.batchRolloverSizeInMbs;
    	      this.batchRolloverTimeInMs = defaults.batchRolloverTimeInMs;
    	      this.batchSizeInKbs = defaults.batchSizeInKbs;
    	      this.batchSizeInNum = defaults.batchSizeInNum;
    	      this.batchTimeInSec = defaults.batchTimeInSec;
    	      this.bucket = defaults.bucket;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dimensions = defaults.dimensions;
    	      this.enableFormattedMessaging = defaults.enableFormattedMessaging;
    	      this.functionId = defaults.functionId;
    	      this.kind = defaults.kind;
    	      this.logGroupId = defaults.logGroupId;
    	      this.logSourceIdentifier = defaults.logSourceIdentifier;
    	      this.metric = defaults.metric;
    	      this.metricNamespace = defaults.metricNamespace;
    	      this.namespace = defaults.namespace;
    	      this.objectNamePrefix = defaults.objectNamePrefix;
    	      this.privateEndpointMetadatas = defaults.privateEndpointMetadatas;
    	      this.streamId = defaults.streamId;
    	      this.topicId = defaults.topicId;
        }

        @CustomType.Setter
        public Builder batchRolloverSizeInMbs(Integer batchRolloverSizeInMbs) {
            if (batchRolloverSizeInMbs == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "batchRolloverSizeInMbs");
            }
            this.batchRolloverSizeInMbs = batchRolloverSizeInMbs;
            return this;
        }
        @CustomType.Setter
        public Builder batchRolloverTimeInMs(Integer batchRolloverTimeInMs) {
            if (batchRolloverTimeInMs == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "batchRolloverTimeInMs");
            }
            this.batchRolloverTimeInMs = batchRolloverTimeInMs;
            return this;
        }
        @CustomType.Setter
        public Builder batchSizeInKbs(Integer batchSizeInKbs) {
            if (batchSizeInKbs == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "batchSizeInKbs");
            }
            this.batchSizeInKbs = batchSizeInKbs;
            return this;
        }
        @CustomType.Setter
        public Builder batchSizeInNum(Integer batchSizeInNum) {
            if (batchSizeInNum == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "batchSizeInNum");
            }
            this.batchSizeInNum = batchSizeInNum;
            return this;
        }
        @CustomType.Setter
        public Builder batchTimeInSec(Integer batchTimeInSec) {
            if (batchTimeInSec == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "batchTimeInSec");
            }
            this.batchTimeInSec = batchTimeInSec;
            return this;
        }
        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder dimensions(List<GetServiceConnectorTargetDimension> dimensions) {
            if (dimensions == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "dimensions");
            }
            this.dimensions = dimensions;
            return this;
        }
        public Builder dimensions(GetServiceConnectorTargetDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        @CustomType.Setter
        public Builder enableFormattedMessaging(Boolean enableFormattedMessaging) {
            if (enableFormattedMessaging == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "enableFormattedMessaging");
            }
            this.enableFormattedMessaging = enableFormattedMessaging;
            return this;
        }
        @CustomType.Setter
        public Builder functionId(String functionId) {
            if (functionId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "functionId");
            }
            this.functionId = functionId;
            return this;
        }
        @CustomType.Setter
        public Builder kind(String kind) {
            if (kind == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "kind");
            }
            this.kind = kind;
            return this;
        }
        @CustomType.Setter
        public Builder logGroupId(String logGroupId) {
            if (logGroupId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "logGroupId");
            }
            this.logGroupId = logGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder logSourceIdentifier(String logSourceIdentifier) {
            if (logSourceIdentifier == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "logSourceIdentifier");
            }
            this.logSourceIdentifier = logSourceIdentifier;
            return this;
        }
        @CustomType.Setter
        public Builder metric(String metric) {
            if (metric == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "metric");
            }
            this.metric = metric;
            return this;
        }
        @CustomType.Setter
        public Builder metricNamespace(String metricNamespace) {
            if (metricNamespace == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "metricNamespace");
            }
            this.metricNamespace = metricNamespace;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder objectNamePrefix(String objectNamePrefix) {
            if (objectNamePrefix == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "objectNamePrefix");
            }
            this.objectNamePrefix = objectNamePrefix;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointMetadatas(List<GetServiceConnectorTargetPrivateEndpointMetadata> privateEndpointMetadatas) {
            if (privateEndpointMetadatas == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "privateEndpointMetadatas");
            }
            this.privateEndpointMetadatas = privateEndpointMetadatas;
            return this;
        }
        public Builder privateEndpointMetadatas(GetServiceConnectorTargetPrivateEndpointMetadata... privateEndpointMetadatas) {
            return privateEndpointMetadatas(List.of(privateEndpointMetadatas));
        }
        @CustomType.Setter
        public Builder streamId(String streamId) {
            if (streamId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "streamId");
            }
            this.streamId = streamId;
            return this;
        }
        @CustomType.Setter
        public Builder topicId(String topicId) {
            if (topicId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorTarget", "topicId");
            }
            this.topicId = topicId;
            return this;
        }
        public GetServiceConnectorTarget build() {
            final var _resultValue = new GetServiceConnectorTarget();
            _resultValue.batchRolloverSizeInMbs = batchRolloverSizeInMbs;
            _resultValue.batchRolloverTimeInMs = batchRolloverTimeInMs;
            _resultValue.batchSizeInKbs = batchSizeInKbs;
            _resultValue.batchSizeInNum = batchSizeInNum;
            _resultValue.batchTimeInSec = batchTimeInSec;
            _resultValue.bucket = bucket;
            _resultValue.compartmentId = compartmentId;
            _resultValue.dimensions = dimensions;
            _resultValue.enableFormattedMessaging = enableFormattedMessaging;
            _resultValue.functionId = functionId;
            _resultValue.kind = kind;
            _resultValue.logGroupId = logGroupId;
            _resultValue.logSourceIdentifier = logSourceIdentifier;
            _resultValue.metric = metric;
            _resultValue.metricNamespace = metricNamespace;
            _resultValue.namespace = namespace;
            _resultValue.objectNamePrefix = objectNamePrefix;
            _resultValue.privateEndpointMetadatas = privateEndpointMetadatas;
            _resultValue.streamId = streamId;
            _resultValue.topicId = topicId;
            return _resultValue;
        }
    }
}
