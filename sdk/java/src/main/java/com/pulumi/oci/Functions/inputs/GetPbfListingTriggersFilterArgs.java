// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPbfListingTriggersFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final GetPbfListingTriggersFilterArgs Empty = new GetPbfListingTriggersFilterArgs();

    /**
     * A filter to return only resources that match the service trigger source of a PBF.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return A filter to return only resources that match the service trigger source of a PBF.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Output<Boolean> regex;

    public Optional<Output<Boolean>> regex() {
        return Optional.ofNullable(this.regex);
    }

    @Import(name="values", required=true)
    private Output<List<String>> values;

    public Output<List<String>> values() {
        return this.values;
    }

    private GetPbfListingTriggersFilterArgs() {}

    private GetPbfListingTriggersFilterArgs(GetPbfListingTriggersFilterArgs $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPbfListingTriggersFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPbfListingTriggersFilterArgs $;

        public Builder() {
            $ = new GetPbfListingTriggersFilterArgs();
        }

        public Builder(GetPbfListingTriggersFilterArgs defaults) {
            $ = new GetPbfListingTriggersFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name A filter to return only resources that match the service trigger source of a PBF.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the service trigger source of a PBF.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public Builder regex(@Nullable Output<Boolean> regex) {
            $.regex = regex;
            return this;
        }

        public Builder regex(Boolean regex) {
            return regex(Output.of(regex));
        }

        public Builder values(Output<List<String>> values) {
            $.values = values;
            return this;
        }

        public Builder values(List<String> values) {
            return values(Output.of(values));
        }

        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetPbfListingTriggersFilterArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetPbfListingTriggersFilterArgs", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetPbfListingTriggersFilterArgs", "values");
            }
            return $;
        }
    }

}
