// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSupportedHostShapesFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final GetSupportedHostShapesFilterArgs Empty = new GetSupportedHostShapesFilterArgs();

    /**
     * A filter to return only resources that match the given name exactly.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return A filter to return only resources that match the given name exactly.
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

    private GetSupportedHostShapesFilterArgs() {}

    private GetSupportedHostShapesFilterArgs(GetSupportedHostShapesFilterArgs $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSupportedHostShapesFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSupportedHostShapesFilterArgs $;

        public Builder() {
            $ = new GetSupportedHostShapesFilterArgs();
        }

        public Builder(GetSupportedHostShapesFilterArgs defaults) {
            $ = new GetSupportedHostShapesFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name A filter to return only resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the given name exactly.
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

        public GetSupportedHostShapesFilterArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetSupportedHostShapesFilterArgs", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetSupportedHostShapesFilterArgs", "values");
            }
            return $;
        }
    }

}
