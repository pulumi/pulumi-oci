// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class FleetOperationLog {
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
     * 
     */
    private String logGroupId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
     * 
     */
    private String logId;

    private FleetOperationLog() {}
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
     * 
     */
    public String logId() {
        return this.logId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FleetOperationLog defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String logGroupId;
        private String logId;
        public Builder() {}
        public Builder(FleetOperationLog defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        @CustomType.Setter
        public Builder logGroupId(String logGroupId) {
            this.logGroupId = Objects.requireNonNull(logGroupId);
            return this;
        }
        @CustomType.Setter
        public Builder logId(String logId) {
            this.logId = Objects.requireNonNull(logId);
            return this;
        }
        public FleetOperationLog build() {
            final var o = new FleetOperationLog();
            o.logGroupId = logGroupId;
            o.logId = logId;
            return o;
        }
    }
}