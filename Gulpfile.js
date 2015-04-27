// Require and load our packages
var gulp    = require('gulp'),
jshint  = require('gulp-jshint'),
notify  = require('gulp-notify'),
mocha   = require('gulp-mocha'),
reporter= require('mocha-spec-reporter-async');


// Reference our app files for easy reference in out gulp tasks
var paths = {
  scripts: ['.'],  // you can use glob pattern
  server: {
    index: 'index.js',
    specs: ['./test/*.js'],
    libs: ['./lib/*.js']
  }
};

// run mocha specs
gulp.task('test', function(){
  return gulp.src(paths.server.specs, {read: false})
  .pipe(mocha({
    reporter: 'mocha-spec-reporter-async',
    growl: true,
    ui: 'bdd'
  }));
});

// Autorun specs
gulp.task('test:watch', function() {
  gulp.watch([paths.server.index, paths.server.specs, paths.server.libs], ['test']);
});

// lint your js files
gulp.task('jshint', function(){
  gulp.src(paths.scripts)
  .pipe(jshint())
  .pipe(jshint.reporter('default'))
  .pipe(notify({message: 'Linitng complete'}));
});
