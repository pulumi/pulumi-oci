// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetConsoleHistoriesFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final GetConsoleHistoriesFilterArgs Empty = new GetConsoleHistoriesFilterArgs();

    @Import(name="name", required=true)
    private Output<String> name;

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

    private GetConsoleHistoriesFilterArgs() {}

    private GetConsoleHistoriesFilterArgs(GetConsoleHistoriesFilterArgs $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetConsoleHistoriesFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConsoleHistoriesFilterArgs $;

        public Builder() {
            $ = new GetConsoleHistoriesFilterArgs();
        }

        public Builder(GetConsoleHistoriesFilterArgs defaults) {
            $ = new GetConsoleHistoriesFilterArgs(Objects.requireNonNull(defaults));
        }

        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

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

        public GetConsoleHistoriesFilterArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetConsoleHistoriesFilterArgs", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetConsoleHistoriesFilterArgs", "values");
            }
            return $;
        }
    }

}
