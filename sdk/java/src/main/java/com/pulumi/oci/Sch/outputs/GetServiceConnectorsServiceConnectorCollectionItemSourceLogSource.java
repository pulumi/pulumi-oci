// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetServiceConnectorsServiceConnectorCollectionItemSourceLogSource {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for this request.
     * 
     */
    private final String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Logging Analytics log group.
     * 
     */
    private final String logGroupId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
     * 
     */
    private final String logId;

    @CustomType.Constructor
    private GetServiceConnectorsServiceConnectorCollectionItemSourceLogSource(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("logGroupId") String logGroupId,
        @CustomType.Parameter("logId") String logId) {
        this.compartmentId = compartmentId;
        this.logGroupId = logGroupId;
        this.logId = logId;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for this request.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Logging Analytics log group.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
     * 
     */
    public String logId() {
        return this.logId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceConnectorsServiceConnectorCollectionItemSourceLogSource defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String logGroupId;
        private String logId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetServiceConnectorsServiceConnectorCollectionItemSourceLogSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder logGroupId(String logGroupId) {
            this.logGroupId = Objects.requireNonNull(logGroupId);
            return this;
        }
        public Builder logId(String logId) {
            this.logId = Objects.requireNonNull(logId);
            return this;
        }        public GetServiceConnectorsServiceConnectorCollectionItemSourceLogSource build() {
            return new GetServiceConnectorsServiceConnectorCollectionItemSourceLogSource(compartmentId, logGroupId, logId);
        }
    }
}
