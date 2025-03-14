// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetSystemVersionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSystemVersionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSystemVersionsPlainArgs Empty = new GetSystemVersionsPlainArgs();

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetSystemVersionsFilter> filters;

    public Optional<List<GetSystemVersionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Specifies gi version query parameter.
     * 
     */
    @Import(name="giVersion", required=true)
    private String giVersion;

    /**
     * @return Specifies gi version query parameter.
     * 
     */
    public String giVersion() {
        return this.giVersion;
    }

    /**
     * Specifies shape query parameter.
     * 
     */
    @Import(name="shape", required=true)
    private String shape;

    /**
     * @return Specifies shape query parameter.
     * 
     */
    public String shape() {
        return this.shape;
    }

    private GetSystemVersionsPlainArgs() {}

    private GetSystemVersionsPlainArgs(GetSystemVersionsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.giVersion = $.giVersion;
        this.shape = $.shape;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSystemVersionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSystemVersionsPlainArgs $;

        public Builder() {
            $ = new GetSystemVersionsPlainArgs();
        }

        public Builder(GetSystemVersionsPlainArgs defaults) {
            $ = new GetSystemVersionsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetSystemVersionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSystemVersionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param giVersion Specifies gi version query parameter.
         * 
         * @return builder
         * 
         */
        public Builder giVersion(String giVersion) {
            $.giVersion = giVersion;
            return this;
        }

        /**
         * @param shape Specifies shape query parameter.
         * 
         * @return builder
         * 
         */
        public Builder shape(String shape) {
            $.shape = shape;
            return this;
        }

        public GetSystemVersionsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetSystemVersionsPlainArgs", "compartmentId");
            }
            if ($.giVersion == null) {
                throw new MissingRequiredPropertyException("GetSystemVersionsPlainArgs", "giVersion");
            }
            if ($.shape == null) {
                throw new MissingRequiredPropertyException("GetSystemVersionsPlainArgs", "shape");
            }
            return $;
        }
    }

}
