// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DedicatedVantagePointDvpStackDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DedicatedVantagePointDvpStackDetailsArgs Empty = new DedicatedVantagePointDvpStackDetailsArgs();

    /**
     * (Updatable) Stack [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    @Import(name="dvpStackId", required=true)
    private Output<String> dvpStackId;

    /**
     * @return (Updatable) Stack [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    public Output<String> dvpStackId() {
        return this.dvpStackId;
    }

    /**
     * (Updatable) Type of stack.
     * 
     */
    @Import(name="dvpStackType", required=true)
    private Output<String> dvpStackType;

    /**
     * @return (Updatable) Type of stack.
     * 
     */
    public Output<String> dvpStackType() {
        return this.dvpStackType;
    }

    /**
     * (Updatable) Stream [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    @Import(name="dvpStreamId", required=true)
    private Output<String> dvpStreamId;

    /**
     * @return (Updatable) Stream [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    public Output<String> dvpStreamId() {
        return this.dvpStreamId;
    }

    /**
     * (Updatable) Version of the dedicated vantage point.
     * 
     */
    @Import(name="dvpVersion", required=true)
    private Output<String> dvpVersion;

    /**
     * @return (Updatable) Version of the dedicated vantage point.
     * 
     */
    public Output<String> dvpVersion() {
        return this.dvpVersion;
    }

    private DedicatedVantagePointDvpStackDetailsArgs() {}

    private DedicatedVantagePointDvpStackDetailsArgs(DedicatedVantagePointDvpStackDetailsArgs $) {
        this.dvpStackId = $.dvpStackId;
        this.dvpStackType = $.dvpStackType;
        this.dvpStreamId = $.dvpStreamId;
        this.dvpVersion = $.dvpVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DedicatedVantagePointDvpStackDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DedicatedVantagePointDvpStackDetailsArgs $;

        public Builder() {
            $ = new DedicatedVantagePointDvpStackDetailsArgs();
        }

        public Builder(DedicatedVantagePointDvpStackDetailsArgs defaults) {
            $ = new DedicatedVantagePointDvpStackDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dvpStackId (Updatable) Stack [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder dvpStackId(Output<String> dvpStackId) {
            $.dvpStackId = dvpStackId;
            return this;
        }

        /**
         * @param dvpStackId (Updatable) Stack [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder dvpStackId(String dvpStackId) {
            return dvpStackId(Output.of(dvpStackId));
        }

        /**
         * @param dvpStackType (Updatable) Type of stack.
         * 
         * @return builder
         * 
         */
        public Builder dvpStackType(Output<String> dvpStackType) {
            $.dvpStackType = dvpStackType;
            return this;
        }

        /**
         * @param dvpStackType (Updatable) Type of stack.
         * 
         * @return builder
         * 
         */
        public Builder dvpStackType(String dvpStackType) {
            return dvpStackType(Output.of(dvpStackType));
        }

        /**
         * @param dvpStreamId (Updatable) Stream [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder dvpStreamId(Output<String> dvpStreamId) {
            $.dvpStreamId = dvpStreamId;
            return this;
        }

        /**
         * @param dvpStreamId (Updatable) Stream [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder dvpStreamId(String dvpStreamId) {
            return dvpStreamId(Output.of(dvpStreamId));
        }

        /**
         * @param dvpVersion (Updatable) Version of the dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder dvpVersion(Output<String> dvpVersion) {
            $.dvpVersion = dvpVersion;
            return this;
        }

        /**
         * @param dvpVersion (Updatable) Version of the dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder dvpVersion(String dvpVersion) {
            return dvpVersion(Output.of(dvpVersion));
        }

        public DedicatedVantagePointDvpStackDetailsArgs build() {
            $.dvpStackId = Objects.requireNonNull($.dvpStackId, "expected parameter 'dvpStackId' to be non-null");
            $.dvpStackType = Objects.requireNonNull($.dvpStackType, "expected parameter 'dvpStackType' to be non-null");
            $.dvpStreamId = Objects.requireNonNull($.dvpStreamId, "expected parameter 'dvpStreamId' to be non-null");
            $.dvpVersion = Objects.requireNonNull($.dvpVersion, "expected parameter 'dvpVersion' to be non-null");
            return $;
        }
    }

}