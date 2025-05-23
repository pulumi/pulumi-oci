// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetServiceConnectorSourceLogSource {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
     * 
     */
    private String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Logging Analytics log group.
     * 
     */
    private String logGroupId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
     * 
     */
    private String logId;

    private GetServiceConnectorSourceLogSource() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
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

    public static Builder builder(GetServiceConnectorSourceLogSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String logGroupId;
        private String logId;
        public Builder() {}
        public Builder(GetServiceConnectorSourceLogSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorSourceLogSource", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder logGroupId(String logGroupId) {
            if (logGroupId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorSourceLogSource", "logGroupId");
            }
            this.logGroupId = logGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder logId(String logId) {
            if (logId == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorSourceLogSource", "logId");
            }
            this.logId = logId;
            return this;
        }
        public GetServiceConnectorSourceLogSource build() {
            final var _resultValue = new GetServiceConnectorSourceLogSource();
            _resultValue.compartmentId = compartmentId;
            _resultValue.logGroupId = logGroupId;
            _resultValue.logId = logId;
            return _resultValue;
        }
    }
}
