// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Sch.outputs.GetServiceConnectorsServiceConnectorCollectionItemTaskPrivateEndpointMetadata;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetServiceConnectorsServiceConnectorCollectionItemTask {
    /**
     * @return Size limit (kilobytes) for batch sent to invoke the function.
     * 
     */
    private Integer batchSizeInKbs;
    /**
     * @return Time limit (seconds) for batch sent to invoke the function.
     * 
     */
    private Integer batchTimeInSec;
    /**
     * @return A filter or mask to limit the source used in the flow defined by the connector.
     * 
     */
    private String condition;
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
     * @return The private endpoint metadata for the connector&#39;s source or target.
     * 
     */
    private List<GetServiceConnectorsServiceConnectorCollectionItemTaskPrivateEndpointMetadata> privateEndpointMetadatas;

    private GetServiceConnectorsServiceConnectorCollectionItemTask() {}
    /**
     * @return Size limit (kilobytes) for batch sent to invoke the function.
     * 
     */
    public Integer batchSizeInKbs() {
        return this.batchSizeInKbs;
    }
    /**
     * @return Time limit (seconds) for batch sent to invoke the function.
     * 
     */
    public Integer batchTimeInSec() {
        return this.batchTimeInSec;
    }
    /**
     * @return A filter or mask to limit the source used in the flow defined by the connector.
     * 
     */
    public String condition() {
        return this.condition;
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
     * @return The private endpoint metadata for the connector&#39;s source or target.
     * 
     */
    public List<GetServiceConnectorsServiceConnectorCollectionItemTaskPrivateEndpointMetadata> privateEndpointMetadatas() {
        return this.privateEndpointMetadatas;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceConnectorsServiceConnectorCollectionItemTask defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer batchSizeInKbs;
        private Integer batchTimeInSec;
        private String condition;
        private String functionId;
        private String kind;
        private List<GetServiceConnectorsServiceConnectorCollectionItemTaskPrivateEndpointMetadata> privateEndpointMetadatas;
        public Builder() {}
        public Builder(GetServiceConnectorsServiceConnectorCollectionItemTask defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.batchSizeInKbs = defaults.batchSizeInKbs;
    	      this.batchTimeInSec = defaults.batchTimeInSec;
    	      this.condition = defaults.condition;
    	      this.functionId = defaults.functionId;
    	      this.kind = defaults.kind;
    	      this.privateEndpointMetadatas = defaults.privateEndpointMetadatas;
        }

        @CustomType.Setter
        public Builder batchSizeInKbs(Integer batchSizeInKbs) {
            if (batchSizeInKbs == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemTask", "batchSizeInKbs");
            }
            this.batchSizeInKbs = batchSizeInKbs;
            return this;
        }
        @CustomType.Setter
        public Builder batchTimeInSec(Integer batchTimeInSec) {
            if (batchTimeInSec == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemTask", "batchTimeInSec");
            }
            this.batchTimeInSec = batchTimeInSec;
            return this;
        }
        @CustomType.Setter
        public Builder condition(String condition) {
            if (condition == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemTask", "condition");
            }
            this.condition = condition;
            return this;
        }
        @CustomType.Setter
        public Builder functionId(String functionId) {
            if (functionId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemTask", "functionId");
            }
            this.functionId = functionId;
            return this;
        }
        @CustomType.Setter
        public Builder kind(String kind) {
            if (kind == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemTask", "kind");
            }
            this.kind = kind;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointMetadatas(List<GetServiceConnectorsServiceConnectorCollectionItemTaskPrivateEndpointMetadata> privateEndpointMetadatas) {
            if (privateEndpointMetadatas == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemTask", "privateEndpointMetadatas");
            }
            this.privateEndpointMetadatas = privateEndpointMetadatas;
            return this;
        }
        public Builder privateEndpointMetadatas(GetServiceConnectorsServiceConnectorCollectionItemTaskPrivateEndpointMetadata... privateEndpointMetadatas) {
            return privateEndpointMetadatas(List.of(privateEndpointMetadatas));
        }
        public GetServiceConnectorsServiceConnectorCollectionItemTask build() {
            final var _resultValue = new GetServiceConnectorsServiceConnectorCollectionItemTask();
            _resultValue.batchSizeInKbs = batchSizeInKbs;
            _resultValue.batchTimeInSec = batchTimeInSec;
            _resultValue.condition = condition;
            _resultValue.functionId = functionId;
            _resultValue.kind = kind;
            _resultValue.privateEndpointMetadatas = privateEndpointMetadatas;
            return _resultValue;
        }
    }
}
