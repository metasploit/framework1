##
# MSFModule.pm - exploit module loader for the metasploit framework interface
##

package MSFModule;
$VERSION = 1.0;

sub new {
    my ($cls, $arg) = @_;
    my $obj = {};
    bless $obj, $cls;   
    $obj->_init($arg);
    return $obj;
}

sub _init {
    my ($obj, $arg) = @_;
    my $options = {};
    my $buffer;
    my $dynpkg = "MSFModule_" . scalar($obj);
    $dynpkg =~ s/=|\(|\)//g;
    
    local *TMP;
    
    $obj->Loaded(0);

    if (! -f $arg || ! -r $arg)
    {
        $obj->Error("Could not open module: not a readable file!");
        return undef;   
    }
    
    # open the module file 
    if ( open(TMP, "<$arg") )
    {
        while (<TMP>) { $buffer .= $_;}
        close (TMP);
    } else {
        $obj->Error("Could not open module: $!");
        return undef;
    }
    
    # create a temporary namespace for it
    $buffer = "package " . $dynpkg . ";\n" . $buffer;

    eval($buffer);
    if ($@)
    {
        $obj->Error("Load error in module: $@");
        return undef;
    }
    
    # load the static fields
    $obj->Description(eval('$'.$dynpkg.'::Description'));
    $obj->Version(eval('$'.$dynpkg.'::Version'));
    $obj->Author(eval('$'.$dynpkg.'::Author'));
    $obj->Group(eval('$'.$dynpkg.'::Group'));
    $obj->Name(eval('$'.$dynpkg.'::Name'));
    $obj->URL(eval('$'.$dynpkg.'::URL'));

    # load the subroutine references
    $obj->{Payloads}    = eval('\&'.$dynpkg.'::Payloads'); 
    $obj->{Exploit}     = eval('\&'.$dynpkg.'::Exploit'); 
    $obj->{Options}     = eval('\&'.$dynpkg.'::Options');  
    $obj->{Check}       = eval('\&'.$dynpkg.'::Check');
    $obj->{Init}        = eval('\&'.$dynpkg.'::Init');

    $obj->Init();
    $obj->Loaded(1);
    
    return 1;
}

sub Exploit {
    my ($obj, $opt) = @_;
    return $obj->{Exploit}->($obj, $opt);   
}

sub Check {
    my ($obj, $opt) = @_;
    return $obj->{Check}->($obj, $opt);   
}

sub ModuleOptions {
    my ($obj, $opt) = @_;
    return $obj->{Options}->($obj, $opt);   
}

sub Payloads {
    my ($obj, $opt) = @_;
    return $obj->{Payloads}->($obj, $opt);   
}

sub Init {
    my ($obj, $opt) = @_;
    return $obj->{Init}->($obj, $opt);   
}

sub Settings {
    my $obj = shift();
    if (@_) { $obj->{Settings} = shift(); }
    return $obj->{Settings};
}

sub Name {
    my $obj = shift();
    if (@_) { $obj->{Name} = shift(); }
    return $obj->{Name};
}

sub Description {
    my $obj = shift();
    if (@_) { $obj->{Description} = shift(); }
    return $obj->{Description};
}

sub Version {
    my $obj = shift();
    if (@_) { $obj->{Version} = shift(); }
    return $obj->{Version};
}

sub Author {
    my $obj = shift();
    if (@_) { $obj->{Author} = shift(); }
    return $obj->{Author};
}

sub URL {
    my $obj = shift();
    if (@_) { $obj->{URL} = shift(); }
    return $obj->{URL};
}

sub Group {
    my $obj = shift();
    if (@_) { $obj->{Group} = shift(); }
    return $obj->{Group};
}

sub NeedPayload {
    my $obj = shift();
    if (@_) { $obj->{NeedPayload} = shift(); }
    return $obj->{NeedPayload};
}

sub Error {
    my $obj = shift();
    if (@_) { $obj->{Error} = shift(); }
    return $obj->{Error};
}

sub Loaded {
    my $obj = shift();
    if (@_) { $obj->{Loaded} = shift(); }
    return $obj->{Loaded};
}

1;
