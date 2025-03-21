// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetMonitorPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMonitorPlainArgs Empty = new GetMonitorPlainArgs();

    /**
     * The APM domain ID the request is intended for.
     * 
     */
    @Import(name="apmDomainId", required=true)
    private String apmDomainId;

    /**
     * @return The APM domain ID the request is intended for.
     * 
     */
    public String apmDomainId() {
        return this.apmDomainId;
    }

    /**
     * The OCID of the monitor.
     * 
     */
    @Import(name="monitorId", required=true)
    private String monitorId;

    /**
     * @return The OCID of the monitor.
     * 
     */
    public String monitorId() {
        return this.monitorId;
    }

    private GetMonitorPlainArgs() {}

    private GetMonitorPlainArgs(GetMonitorPlainArgs $) {
        this.apmDomainId = $.apmDomainId;
        this.monitorId = $.monitorId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMonitorPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMonitorPlainArgs $;

        public Builder() {
            $ = new GetMonitorPlainArgs();
        }

        public Builder(GetMonitorPlainArgs defaults) {
            $ = new GetMonitorPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param apmDomainId The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(String apmDomainId) {
            $.apmDomainId = apmDomainId;
            return this;
        }

        /**
         * @param monitorId The OCID of the monitor.
         * 
         * @return builder
         * 
         */
        public Builder monitorId(String monitorId) {
            $.monitorId = monitorId;
            return this;
        }

        public GetMonitorPlainArgs build() {
            if ($.apmDomainId == null) {
                throw new MissingRequiredPropertyException("GetMonitorPlainArgs", "apmDomainId");
            }
            if ($.monitorId == null) {
                throw new MissingRequiredPropertyException("GetMonitorPlainArgs", "monitorId");
            }
            return $;
        }
    }

}
