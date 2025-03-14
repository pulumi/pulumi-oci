// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetFleetCryptoAnalysisResultPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFleetCryptoAnalysisResultPlainArgs Empty = new GetFleetCryptoAnalysisResultPlainArgs();

    /**
     * The OCID of the analysis result.
     * 
     */
    @Import(name="cryptoAnalysisResultId", required=true)
    private String cryptoAnalysisResultId;

    /**
     * @return The OCID of the analysis result.
     * 
     */
    public String cryptoAnalysisResultId() {
        return this.cryptoAnalysisResultId;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    @Import(name="fleetId", required=true)
    private String fleetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }

    private GetFleetCryptoAnalysisResultPlainArgs() {}

    private GetFleetCryptoAnalysisResultPlainArgs(GetFleetCryptoAnalysisResultPlainArgs $) {
        this.cryptoAnalysisResultId = $.cryptoAnalysisResultId;
        this.fleetId = $.fleetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFleetCryptoAnalysisResultPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFleetCryptoAnalysisResultPlainArgs $;

        public Builder() {
            $ = new GetFleetCryptoAnalysisResultPlainArgs();
        }

        public Builder(GetFleetCryptoAnalysisResultPlainArgs defaults) {
            $ = new GetFleetCryptoAnalysisResultPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param cryptoAnalysisResultId The OCID of the analysis result.
         * 
         * @return builder
         * 
         */
        public Builder cryptoAnalysisResultId(String cryptoAnalysisResultId) {
            $.cryptoAnalysisResultId = cryptoAnalysisResultId;
            return this;
        }

        /**
         * @param fleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(String fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        public GetFleetCryptoAnalysisResultPlainArgs build() {
            if ($.cryptoAnalysisResultId == null) {
                throw new MissingRequiredPropertyException("GetFleetCryptoAnalysisResultPlainArgs", "cryptoAnalysisResultId");
            }
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetFleetCryptoAnalysisResultPlainArgs", "fleetId");
            }
            return $;
        }
    }

}
