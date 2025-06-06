// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Vbs;

import com.pulumi.core.Output;
import com.pulumi.core.TypeShape;
import com.pulumi.deployment.Deployment;
import com.pulumi.deployment.InvokeOptions;
import com.pulumi.deployment.InvokeOutputOptions;
import com.pulumi.oci.Utilities;
import com.pulumi.oci.Vbs.inputs.GetInstVbsInstanceArgs;
import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancePlainArgs;
import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancesArgs;
import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancesPlainArgs;
import com.pulumi.oci.Vbs.outputs.GetInstVbsInstanceResult;
import com.pulumi.oci.Vbs.outputs.GetInstVbsInstancesResult;
import java.util.concurrent.CompletableFuture;

public final class VbsFunctions {
    /**
     * This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Gets a VbsInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstance = VbsFunctions.getInstVbsInstance(GetInstVbsInstanceArgs.builder()
     *             .vbsInstanceId(testVbsInstanceOciVbsInstVbsInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetInstVbsInstanceResult> getInstVbsInstance(GetInstVbsInstanceArgs args) {
        return getInstVbsInstance(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Gets a VbsInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstance = VbsFunctions.getInstVbsInstance(GetInstVbsInstanceArgs.builder()
     *             .vbsInstanceId(testVbsInstanceOciVbsInstVbsInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetInstVbsInstanceResult> getInstVbsInstancePlain(GetInstVbsInstancePlainArgs args) {
        return getInstVbsInstancePlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Gets a VbsInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstance = VbsFunctions.getInstVbsInstance(GetInstVbsInstanceArgs.builder()
     *             .vbsInstanceId(testVbsInstanceOciVbsInstVbsInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetInstVbsInstanceResult> getInstVbsInstance(GetInstVbsInstanceArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Vbs/getInstVbsInstance:getInstVbsInstance", TypeShape.of(GetInstVbsInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Gets a VbsInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstance = VbsFunctions.getInstVbsInstance(GetInstVbsInstanceArgs.builder()
     *             .vbsInstanceId(testVbsInstanceOciVbsInstVbsInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetInstVbsInstanceResult> getInstVbsInstance(GetInstVbsInstanceArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:Vbs/getInstVbsInstance:getInstVbsInstance", TypeShape.of(GetInstVbsInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Gets a VbsInstance by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstanceArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstance = VbsFunctions.getInstVbsInstance(GetInstVbsInstanceArgs.builder()
     *             .vbsInstanceId(testVbsInstanceOciVbsInstVbsInstance.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetInstVbsInstanceResult> getInstVbsInstancePlain(GetInstVbsInstancePlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Vbs/getInstVbsInstance:getInstVbsInstance", TypeShape.of(GetInstVbsInstanceResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Vbs Instances in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Returns a list of VbsInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstances = VbsFunctions.getInstVbsInstances(GetInstVbsInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .id(vbsInstanceId)
     *             .name(vbsInstanceName)
     *             .state(vbsInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetInstVbsInstancesResult> getInstVbsInstances(GetInstVbsInstancesArgs args) {
        return getInstVbsInstances(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Vbs Instances in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Returns a list of VbsInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstances = VbsFunctions.getInstVbsInstances(GetInstVbsInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .id(vbsInstanceId)
     *             .name(vbsInstanceName)
     *             .state(vbsInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetInstVbsInstancesResult> getInstVbsInstancesPlain(GetInstVbsInstancesPlainArgs args) {
        return getInstVbsInstancesPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Vbs Instances in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Returns a list of VbsInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstances = VbsFunctions.getInstVbsInstances(GetInstVbsInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .id(vbsInstanceId)
     *             .name(vbsInstanceName)
     *             .state(vbsInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetInstVbsInstancesResult> getInstVbsInstances(GetInstVbsInstancesArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Vbs/getInstVbsInstances:getInstVbsInstances", TypeShape.of(GetInstVbsInstancesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Vbs Instances in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Returns a list of VbsInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstances = VbsFunctions.getInstVbsInstances(GetInstVbsInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .id(vbsInstanceId)
     *             .name(vbsInstanceName)
     *             .state(vbsInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetInstVbsInstancesResult> getInstVbsInstances(GetInstVbsInstancesArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:Vbs/getInstVbsInstances:getInstVbsInstances", TypeShape.of(GetInstVbsInstancesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Vbs Instances in Oracle Cloud Infrastructure Vbs Inst service.
     * 
     * Returns a list of VbsInstances.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * <pre>
     * {@code
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Vbs.VbsFunctions;
     * import com.pulumi.oci.Vbs.inputs.GetInstVbsInstancesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testVbsInstances = VbsFunctions.getInstVbsInstances(GetInstVbsInstancesArgs.builder()
     *             .compartmentId(compartmentId)
     *             .id(vbsInstanceId)
     *             .name(vbsInstanceName)
     *             .state(vbsInstanceState)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetInstVbsInstancesResult> getInstVbsInstancesPlain(GetInstVbsInstancesPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Vbs/getInstVbsInstances:getInstVbsInstances", TypeShape.of(GetInstVbsInstancesResult.class), args, Utilities.withVersion(options));
    }
}
