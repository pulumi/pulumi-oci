// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetFleetComplianceReportPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFleetComplianceReportPlainArgs Empty = new GetFleetComplianceReportPlainArgs();

    /**
     * compliance report identifier.
     * 
     */
    @Import(name="complianceReportId", required=true)
    private String complianceReportId;

    /**
     * @return compliance report identifier.
     * 
     */
    public String complianceReportId() {
        return this.complianceReportId;
    }

    /**
     * Unique Fleet identifier.
     * 
     */
    @Import(name="fleetId", required=true)
    private String fleetId;

    /**
     * @return Unique Fleet identifier.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }

    private GetFleetComplianceReportPlainArgs() {}

    private GetFleetComplianceReportPlainArgs(GetFleetComplianceReportPlainArgs $) {
        this.complianceReportId = $.complianceReportId;
        this.fleetId = $.fleetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFleetComplianceReportPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFleetComplianceReportPlainArgs $;

        public Builder() {
            $ = new GetFleetComplianceReportPlainArgs();
        }

        public Builder(GetFleetComplianceReportPlainArgs defaults) {
            $ = new GetFleetComplianceReportPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param complianceReportId compliance report identifier.
         * 
         * @return builder
         * 
         */
        public Builder complianceReportId(String complianceReportId) {
            $.complianceReportId = complianceReportId;
            return this;
        }

        /**
         * @param fleetId Unique Fleet identifier.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(String fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        public GetFleetComplianceReportPlainArgs build() {
            if ($.complianceReportId == null) {
                throw new MissingRequiredPropertyException("GetFleetComplianceReportPlainArgs", "complianceReportId");
            }
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetFleetComplianceReportPlainArgs", "fleetId");
            }
            return $;
        }
    }

}
