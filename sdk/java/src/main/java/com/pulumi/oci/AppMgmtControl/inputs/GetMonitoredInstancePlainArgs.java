// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AppMgmtControl.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetMonitoredInstancePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMonitoredInstancePlainArgs Empty = new GetMonitoredInstancePlainArgs();

    /**
     * OCID of monitored instance.
     * 
     */
    @Import(name="monitoredInstanceId", required=true)
    private String monitoredInstanceId;

    /**
     * @return OCID of monitored instance.
     * 
     */
    public String monitoredInstanceId() {
        return this.monitoredInstanceId;
    }

    private GetMonitoredInstancePlainArgs() {}

    private GetMonitoredInstancePlainArgs(GetMonitoredInstancePlainArgs $) {
        this.monitoredInstanceId = $.monitoredInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMonitoredInstancePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMonitoredInstancePlainArgs $;

        public Builder() {
            $ = new GetMonitoredInstancePlainArgs();
        }

        public Builder(GetMonitoredInstancePlainArgs defaults) {
            $ = new GetMonitoredInstancePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param monitoredInstanceId OCID of monitored instance.
         * 
         * @return builder
         * 
         */
        public Builder monitoredInstanceId(String monitoredInstanceId) {
            $.monitoredInstanceId = monitoredInstanceId;
            return this;
        }

        public GetMonitoredInstancePlainArgs build() {
            $.monitoredInstanceId = Objects.requireNonNull($.monitoredInstanceId, "expected parameter 'monitoredInstanceId' to be non-null");
            return $;
        }
    }

}